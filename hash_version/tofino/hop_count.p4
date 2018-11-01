/*************************************************************************
    > File Name: hop_count.c
    > Author:
    > Mail:
    > Created Time: Fri 11 May 2018 9:12:19 AM CST
************************************************************************/

#include "includes/headers.p4"
#include "includes/parser.p4"

#define HOP_COUNT_SIZE 8
#define HC_BITMAP_SIZE 32
#define HC_COMPUTE_TABLE_SIZE 8
#define HC_COMPUTE_TWICE_TABLE_SIZE 3
#define TCP_SESSION_MAP_BITS 8
#define TCP_SESSION_MAP_SIZE 256 // 2^8
#define TCP_SESSION_STATE_SIZE 1
#define IP_TO_HC_INDEX_BITS 23
#define IP_TO_HC_TABLE_SIZE 8388608 // 2^23
#define SAMPLE_VALUE_BITS 3
#define PACKET_TAG_BITS 1

header_type meta_t {
    fields {
        hop_count: HOP_COUNT_SIZE; // Hop Count of this packet
        ip_to_hc_bitmap: HC_BITMAP_SIZE; // Hop Count bitmap in IP2HC
        tcp_session_map_index: TCP_SESSION_MAP_BITS;
        tcp_session_state: TCP_SESSION_STATE_SIZE; // 1:received SYN-ACK 0: exist or none
        tcp_seq_no: 32; // used for writing session_seq register
        tcp_session_seq: 32; // sequence number of SYN-ACK packet
        ip_to_hc_index : IP_TO_HC_INDEX_BITS;
        sample_value : SAMPLE_VALUE_BITS; // Used for sample packets
        hcf_state: 1; // 0: Learning 1: Filtering
        packet_tag: PACKET_TAG_BITS; // 0: Normal 1: Abnormal
        is_inspected: 1; // 0: Not Inspected 1: Inspected
    }
}

metadata meta_t meta;

// The state of the switch, maintained by CPU(control.py)
// need `read` only
register current_state {
    width : 1;
    instance_count : 1;
}
blackbox stateful_alu read_current_state {
    reg: current_state;
    update_lo_1_value: register_lo; /*= do not update*/
    output_value: alu_lo;
    output_dst: meta.hcf_state;
}



// The number(sampled) of abnormal packet per period
// write only
register abnormal_counter {
    width : 32;
    instance_count : 1;
}
blackbox stateful_alu update_abnormal_counter {
    reg: abnormal_counter;
    update_lo_1_value: register_lo + 1;
    initial_register_lo_value: 0;
}

action check_hcf(is_inspected) {
    read_current_state.execute_stateful_alu(0);
    modify_field(meta.is_inspected, is_inspected);
}

// Used to get state(0:learning 1:filtering) of switch
// and judge whether the packet should be inspect by HCF
table hcf_check_table {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions { check_hcf; }
}

action sample_packet() {
    modify_field_rng_uniform(meta.sample_value, 0, 2 ^ SAMPLE_VALUE_BITS - 1);
}

// Sample packets for computing abnormal packets per period
table packet_sample_table {
    actions { sample_packet; }
}

action _drop() {
    drop();
}

action _nop() {
}

action tag_normal() {
    modify_field(meta.packet_tag, 0);
}

// Tag the packet as normal
table packet_normal_table {
    actions { tag_normal; }
}

action tag_abnormal() {
    modify_field(meta.packet_tag, 1);
}

// Tag the packet as abnormal
table packet_abnormal_table {
    actions { tag_abnormal; }
}

action compute_hc(initial_ttl) {
    subtract(meta.hop_count, initial_ttl, ipv4.ttl);
}

// According to final TTL, select initial TTL and compute hop count
table hc_compute_table {
    reads {
        ipv4.ttl : range;
    }
    actions {
        compute_hc;
    }
    size: HC_COMPUTE_TABLE_SIZE;
}

// Another for different pipeline
table hc_compute_table_copy {
    reads {
        ipv4.ttl : range;
    }
    actions {
        compute_hc;
    }
    size: HC_COMPUTE_TABLE_SIZE;
}

// The relation table between source IP and hop count
// Now, IP2HC use source IP's 23bit-prefix's hash value as index
// and store hop-count's bit-map(Most hop count smaller than 30)
// need `read` and `write`
register ip_to_hc {
    width : HC_BITMAP_SIZE;
    instance_count : IP_TO_HC_TABLE_SIZE;
}
blackbox stateful_alu read_ip_to_hc {
    reg: ip_to_hc;
    update_lo_1_value: register_lo;
    output_value: alu_lo;
    output_dst: meta.ip_to_hc_bitmap;
}
blackbox stateful_alu write_ip_to_hc {
    reg: ip_to_hc;
    update_lo_1_value: meta.ip_to_hc_bitmap;
    output_value: alu_lo;
    output_dst: meta.ip_to_hc_bitmap;
}


field_list ipsrc_hash_fields {
    ipv4.srcAddr;
}

field_list_calculation ipsrc_map_hash {
    input {
        ipsrc_hash_fields;
    }
    algorithm : crc16;
    output_width : IP_TO_HC_INDEX_BITS;
}

action inspect_hc() {
    modify_field_with_hash_based_offset(
        meta.ip_to_hc_index, 0,
        ipsrc_map_hash, IP_TO_HC_TABLE_SIZE
    );
    read_ip_to_hc.execute_stateful_alu(meta.ip_to_hc_index);
}

// Get the origin hop count of this source IP
table hc_inspect_table {
    actions { inspect_hc; }
}

// Because near initial TTL pair: (30, 32) and (60, 64),
// so re-select initial TTL and re-compute hop count
table hc_compute_twice_table {
    reads {
        ipv4.ttl : range;
    }
    actions {
        _nop;
        compute_hc;
    }
    size: HC_COMPUTE_TABLE_SIZE;
}

action learning_abnormal() {
    update_abnormal_counter.execute_stateful_alu(0);
    tag_normal();
}

action filtering_sample_abnormal() {
    update_abnormal_counter.execute_stateful_alu(0);
    tag_abnormal();
}

action filtering_other_abnormal() {
    tag_abnormal();
}

// If the packet is judged as abnormal because its suspected hop-count,
// handle it according to the switch state and whether the packet is sampled.
// For learning state: if the packet is sampled, just update abnormal_counter
// and tag it as normal(don't drop it); if the packet is not sampled, it won't
// go through this table because switch don't check its hop count.
// For filtering state, every abnormal packets should be dropped but update
// abnormal_counter specially for these sampled.
table hc_abnormal_table {
    reads {
        meta.hcf_state : exact;
        meta.sample_value : exact;
    }
    actions {
        learning_abnormal;
        filtering_sample_abnormal;
        filtering_other_abnormal;
    }
}

field_list l3_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation tcp_session_map_hash {
    input {
        l3_hash_fields;
    }
    algorithm : crc16;
    output_width : TCP_SESSION_MAP_BITS;
}

field_list reverse_l3_hash_fields {
    ipv4.dstAddr;
    ipv4.srcAddr;
    ipv4.protocol;
    tcp.dstPort;
    tcp.srcPort;
}

field_list_calculation reverse_tcp_session_map_hash {
    input {
        reverse_l3_hash_fields;
    }
    algorithm : crc16;
    output_width : TCP_SESSION_MAP_BITS;
}

action lookup_session_map() {
    /* dedicated hash version */
    modify_field_with_hash_based_offset(
        meta.tcp_session_map_index, 0,
        tcp_session_map_hash, TCP_SESSION_MAP_SIZE
    );
    read_session_state.execute_stateful_alu(meta.tcp_session_map_index);
    read_session_seq.execute_stateful_alu(meta.tcp_session_map_index);
    /* integrated hash version */
    // read_session_state.execute_stateful_alu_from_hash(tcp_session_map_hash);
    // read_session_seq.execute_stateful_alu_from_hash(tcp_session_map_hash);
}

action lookup_reverse_session_map() {
    /* dedicated hash version */
    modify_field_with_hash_based_offset(
        meta.tcp_session_map_index, 0,
        reverse_tcp_session_map_hash,
        TCP_SESSION_MAP_SIZE
    );
    read_session_state.execute_stateful_alu(meta.tcp_session_map_index);
    read_session_seq.execute_stateful_alu(meta.tcp_session_map_index);
    /* integrated hash version */
    // read_session_state.execute_stateful_alu_from_hash(tcp_session_map_hash);
    // read_session_seq.execute_stateful_alu_from_hash(tcp_session_map_hash);
}

// Get packets' tcp session information. Notice: dual direction packets in one
// flow should belong to same tcp session and use same hash value
table session_check_table {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
        _drop;
        lookup_session_map;
        lookup_reverse_session_map;
    }
}

// Store sesscon state for concurrent tcp connections
// need `read` and `write`
register session_state {
    width : TCP_SESSION_STATE_SIZE;
    instance_count : TCP_SESSION_MAP_SIZE;
}
blackbox stateful_alu read_session_state {
    reg: session_state;
    update_lo_1_value: register_lo;
    output_value: alu_lo;
    output_dst: meta.tcp_session_state;
}
blackbox stateful_alu write_session_state {
    reg: session_state;
    update_lo_1_value: meta.tcp_session_state;
    output_value: alu_lo;
    output_dst: meta.tcp_session_state;
}

// Store sesscon sequince number(SYN-ACK's) for concurrent tcp connections
// need `read` and `write`
register session_seq {
    width : 32;
    instance_count : TCP_SESSION_MAP_SIZE;
}
blackbox stateful_alu read_session_seq {
    reg: session_seq;
    update_lo_1_value: register_lo;
    output_value: alu_lo;
    output_dst: meta.tcp_session_seq;
}
blackbox stateful_alu write_session_seq {
    reg: session_seq;
    update_lo_1_value: meta.tcp_seq_no;
    output_value: alu_lo;
    output_dst: meta.tcp_seqNo;
}

action init_session() {
    modify_field(meta.tcp_session_state, 1);
    write_session_state.execute_stateful_alu(meta.tcp_session_map_index);
    modify_field(meta.tcp_seq_no, tcp.seqNo);
    write_session_seq.execute_stateful_alu(meta.tcp_session_map_index);
}

// Someone is attempting to establish a connection from server
table session_init_table {
    actions {
        init_session;
    }
}

action complete_session() {
    modify_field(meta.tcp_session_state, 0);
    write_session_state.execute_stateful_alu(meta.tcp_session_map_index);
    modify_field_with_hash_based_offset(
        meta.ip_to_hc_index, 0,
        ipsrc_map_hash, IP_TO_HC_TABLE_SIZE
    );
    read_ip_to_hc.execute_stateful_alu(meta.ip_to_hc_index);
    bit_or(meta.ip_to_hc_bitmap, meta.ip_to_hc_bitmap, 1 << meta.hop_count);
    write_ip_to_hc.execute_stateful_alu(meta.ip_to_hc_index);
    tag_normal();
}

// Establish the connection, and update IP2HC
table session_complete_table {
    reads {
        tcp.ack : exact;
    }
    actions {
        tag_abnormal;
        complete_session;
    }
}

action forward_l2(egress_port) {
    modify_field(standard_metadata.egress_spec, egress_port);
}

// Forward table, now it just support layer 2
table l2_forward_table {
    reads {
        meta.packet_tag : exact;
        standard_metadata.ingress_port : exact;
    }
    actions {
        _drop;
        forward_l2;
    }
}

control ingress {
    // Get basic infomation of switch and tcp session
    apply(hcf_check_table);
    apply(session_check_table);
    if (meta.tcp_session_state == 1) {
        // The connection is wainting to be established
        if (tcp.ackNo == meta.tcp_session_seq + 1) {
            // Legal connection, so real hop count to be stored
            apply(hc_compute_table_copy);
            apply(session_complete_table);
        }
        else {
            // Illegal connection attempt
            apply(packet_abnormal_table);
        }
    }
    else if (meta.tcp_session_state == 0) {
        // TCP session has been established or not
        if (tcp.syn == 1 and tcp.ack == 1) {
            // A client is attempting to connect to the server
            apply(session_init_table);
        }
        else if (meta.is_inspected == 1) {
            // Other packets. Anywal, samplet it first
            apply(packet_sample_table);
            if (meta.sample_value == 0 or meta.hcf_state == 1) {
                // The packet is sampled or the switch is in filtering state
                // Compute packet's hop count and refer to its origin hop count
                apply(hc_compute_table);
                apply(hc_inspect_table);
                if (((meta.ip_to_hc_bitmap >> meta.hop_count) & 1) == 0) {
                    // Diverse hop count.The reason may be two initial TTL pairs
                    // So recompute hop coutn for those packets
                    apply(hc_compute_twice_table);
                    if (((meta.ip_to_hc_bitmap >> meta.hop_count) & 1) == 0) {
                        // It must be abnormal packet
                        apply(hc_abnormal_table);
                    }
                    else {
                        // It is normal
                        apply(packet_normal_table);
                    }
                }
                else {
                    // It is normal
                    apply(packet_normal_table);
                }
            }
            else {
                // Do nothing to these packets
                apply(packet_normal_table);
            }
        }
    }
    // Drop abnormal packets and forward normal packets in layer two
    apply(l2_forward_table);
}

control egress {
}
