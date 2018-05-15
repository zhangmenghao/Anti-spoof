/*************************************************************************
    > File Name: hop_count.c
    > Author: 
    > Mail: 
    > Created Time: Fri 11 May 2018 9:12:19 AM CST
************************************************************************/

#include "includes/headers.p4"
#include "includes/parser.p4"

#define HOP_COUNT_SIZE 8
#define HC_COMPUTE_TABLE_SIZE 8
#define HC_COMPUTE_TWICE_TABLE_SIZE 3
#define TCP_SESSION_MAP_BITS 8
#define TCP_SESSION_MAP_SIZE 256 // 2^8
#define TCP_SESSION_STATE_SIZE 8
#define IP_TO_HC_INDEX_BITS 24
#define IP_TO_HC_TABLE_SIZE 16777216 // 2^24
#define SAMPLE_VALUE_BITS 3
#define PACKET_TAG_BITS 1

header_type meta_t {
    fields {
        hop_count: HOP_COUNT_SIZE;
        tcp_session_hc: HOP_COUNT_SIZE;
        tcp_session_map_index: TCP_SESSION_MAP_BITS;
        tcp_session_state: TCP_SESSION_STATE_SIZE; // 1: received SYN-ACK
        tcp_session_seq: 32; // 1: received SYN-ACK
        ip_to_hc_index : IP_TO_HC_INDEX_BITS;
        sample_value : SAMPLE_VALUE_BITS;
        hcf_state: 1; // 0: Learning 1: Filtering
        packet_tag: PACKET_TAG_BITS; // 0: Normal 1: Abnormal
    }
}

metadata meta_t meta;

register current_state {
    width : 1;
    instance_count : 1;
}

action check_hcf() {
    register_read(meta.hcf_state, current_state, 0);
}

table hcf_check_table {
    actions { check_hcf; }
}

action sample_packet() {
    modify_field_rng_uniform(meta.sample_value, 0, 2 ^ SAMPLE_VALUE_BITS - 1);
}

table packet_sample_table {
    actions { sample_packet; }
}

action compute_hc(initial_ttl) {
    subtract(meta.hop_count, initial_ttl, ipv4.ttl);
}

action _drop() {
    drop();
}

action _nop() {
}

action tag_normal() {
    modify_field(meta.packet_tag, 0);
}

table packet_normal_table {
    actions { tag_normal; }
}

action tag_abnormal() {
    modify_field(meta.packet_tag, 1);
}

table packet_abnormal_table {
    actions { tag_abnormal; }
}

table hc_compute_table {
    reads {
        ipv4.ttl: range;
    }
    actions {
        compute_hc;
    }
    size: HC_COMPUTE_TABLE_SIZE;
}

table hc_compute_table_copy {
    reads {
        ipv4.ttl: range;
    }
    actions {
        compute_hc;
    }
    size: HC_COMPUTE_TABLE_SIZE;
}

action inspect_hc() {
    shift_right(meta.ip_to_hc_index, ipv4.dstAddr, 32 - IP_TO_HC_INDEX_BITS);
    register_read(meta.tcp_session_hc, ip_to_hc, meta.ip_to_hc_index);
}

table hc_inspect_table {
    actions { inspect_hc; }
}

table hc_compute_twice_table {
    reads {
        ipv4.ttl: range;
    }
    actions {
        _nop;
        compute_hc;
    }
    size: HC_COMPUTE_TABLE_SIZE;
}

counter abnormal_counter {
    type : packets;
    instance_count : 1;
}

action learning_abnormal() {
    count(abnormal_counter, 0);
    tag_normal();
}

action filtering_sample_abnormal() {
    count(abnormal_counter, 0);
    tag_abnormal();
}

action filtering_other_abnormal() {
    tag_abnormal();
}

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
    modify_field_with_hash_based_offset(
        meta.tcp_session_map_index, 0,
        tcp_session_map_hash, TCP_SESSION_MAP_SIZE
    );
    register_read(
        meta.tcp_session_state, session_state, 
        meta.tcp_session_map_index
    );
    register_read(
        meta.tcp_session_seq, session_seq,
        meta.tcp_session_map_index
    );
}

action lookup_reverse_session_map() {
    modify_field_with_hash_based_offset(
        meta.tcp_session_map_index, 0,
        reverse_tcp_session_map_hash,
        TCP_SESSION_MAP_SIZE
    );
    register_read(
        meta.tcp_session_state, session_state, 
        meta.tcp_session_map_index
    );
    register_read(
        meta.tcp_session_seq, session_seq,
        meta.tcp_session_map_index
    );
}

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

register session_state {
    width : TCP_SESSION_STATE_SIZE;
    instance_count : TCP_SESSION_MAP_SIZE;
} 

register session_seq {
    width : 32;
    instance_count : TCP_SESSION_MAP_SIZE;
} 

action init_session() {
    register_write(session_state, meta.tcp_session_map_index, 1);
    register_write(session_seq, meta.tcp_session_map_index, tcp.seqNo);
}

table session_init_table {
    actions {
        init_session;
    }
}

register ip_to_hc {
    width : 8;
    instance_count : IP_TO_HC_TABLE_SIZE;
}

action complete_session() {
    register_write(session_state, meta.tcp_session_map_index, 0);
    shift_right(meta.ip_to_hc_index, ipv4.dstAddr, 32 - IP_TO_HC_INDEX_BITS);
    register_write(ip_to_hc, meta.ip_to_hc_index, meta.hop_count);
    tag_normal();
}

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
    apply(hcf_check_table);
    apply(session_check_table);
    if (meta.tcp_session_state == 1) {
        if (tcp.ackNo == meta.tcp_session_seq + 1) {
            apply(hc_compute_table_copy);
            apply(session_complete_table);
        }
        else {
            apply(packet_abnormal_table);
        }
    }
    else if (meta.tcp_session_state == 0) {
        if (tcp.syn == 1 and tcp.ack == 1) {
            apply(session_init_table);
        }
        else {
            apply(packet_sample_table);
            if (meta.sample_value == 0 or meta.hcf_state == 1) {
                apply(hc_compute_table);
                apply(hc_inspect_table);
                if (meta.hop_count != meta.tcp_session_hc) {
                    apply(hc_compute_twice_table);
                    if (meta.hop_count != meta.tcp_session_hc) {
                        apply(hc_abnormal_table);
                    }
                    else {
                        apply(packet_normal_table);
                    }
                }
                else {
                    apply(packet_normal_table);
                }
            }
            else {
                apply(packet_normal_table);
            }
        }
    }
    apply(l2_forward_table);
}

control egress {
}
