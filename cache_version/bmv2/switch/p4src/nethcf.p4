/*******************************************************************************
    > File Name: nethcf.p4
    > Author: Guanyu Li
    > Mail: dracula.guanyu.li@gmail.com
    > Created Time: Fri 11 May 2018 9:12:19 AM CST
******************************************************************************/

#include "includes/headers.p4"
#include "includes/parser.p4"

#define HOP_COUNT_WIDTH 8
#define IP2HC_COUNTER_WIDTH 8
#define TCP_SESSION_INDEX_WIDTH 8
#define TCP_SESSION_TABLE_SIZE 256 // 2^8
#define TCP_SESSION_STATE_WIDTH 1
#define SESSION_MONITOR_RESULT_WIDTH 2
#define TEMPORARY_BITMAP_WIDTH 32
#define TEMPORARY_BITMAP_INDEX_WIDTH 4
#define IP2HC_INDEX_WIDTH 23
#define PACKET_TAG_WIDTH 1

#define HC_COMPUTE_TABLE_SIZE 8
/* #define IP2HC_TABLE_SIZE 65536 // 2^16 */
#define IP2HC_TABLE_SIZE 13
#define TEMPORARY_BITMAP_SIZE 16
#define FORWARD_TABLE_SIZE 10

#define CLONE_SPEC_VALUE 250
#define CONTROLLER_IP_ADDRESS 0xC0A83865 //192.168.56.101
#define CONTROLLER_PORT 3 // Maybe this parameter can be stored in a register
#define PACKET_TRUNCATE_LENGTH 54
#define LEARNING_STATE 0
#define FILTERING_STATE 1
#define ABNORMAL_FLAG 1
#define NORMAL_FLAG 0
#define ABNORMAL_FLAG 1
#define SESSION_MONITOR_NOP 0
#define SESSION_MONITOR_INIT 1
#define SESSION_MONITOR_UPDATE 2
#define SESSION_MONITOR_ABNORMAL 3
#define IP2HC_HOT_THRESHOLD 10

/*******************************************************************************
*****                       Metadata Definition                           ******
*******************************************************************************/

header_type meta_t {
    fields {
        packet_hop_count : HOP_COUNT_WIDTH; // Hop Count of this packet
        ip2hc_hop_count : HOP_COUNT_WIDTH; // Hop Count in ip2hc table
        ip2hc_counter_value : IP2HC_COUNTER_WIDTH;
        // Hit Count in ip2hc_counter table
        tcp_session_index : TCP_SESSION_INDEX_WIDTH;
        tcp_session_state : TCP_SESSION_STATE_WIDTH;
        // 1:received SYN-ACK 0: exist or none
        session_monitor_result : SESSION_MONITOR_RESULT_WIDTH;
        ip2hc_index : IP2HC_INDEX_WIDTH;
        temporary_bitarray : TEMPORARY_BITMAP_WIDTH;
        hop_count_bitarray : TEMPORARY_BITMAP_WIDTH;
        temporary_bitmap_index : TEMPORARY_BITMAP_INDEX_WIDTH;
        tcp_session_seq : 32; // sequence number of SYN-ACK packet
        nethcf_state : 1; // 0: Learning 1: Filtering
        packet_tag : PACKET_TAG_WIDTH; // 0: Normal 1: Abnormal
        nethcf_enable_flag : 1; // 0: Not Inspected 1: Inspected
        ip_for_match : 32; // IP address for searching the ip2hc table
        ip2hc_hit_flag : 1; // 0: Not Hit 1 : Hit
        update_ip2hc_flag : 1; // Whether need to update ip2hc in cache
        ip2hc_valid_flag : 1; // Whether corresponding IP2HC item is dirty
        dirty_hc_hit_flag: 1; 
        // Whether the packet hop count exist in temporary bitmap
        src_dst_ip : 32; // Used to compute tcp session index
        src_dst_port : 16; // Used to compute tcp session index
        ack_seq_diff : 32;
    }
}

metadata meta_t meta;

/*******************************************************************************
*****                 Register and Counter Definition               ******
*******************************************************************************/

// The state of the switch, maintained by CPU(control.py)
register nethcf_state {
    width : 1;
    instance_count : 1;
}

// Save the hit count value of each entry in ip2hc table
register ip2hc_counter {
    width : IP2HC_COUNTER_WIDTH;
    instance_count : IP2HC_TABLE_SIZE;
}

// The flag bit array of ip2hc to identify whether the ip2hc iterm is dirty
register ip2hc_valid_flag {
    width : 1;
    instance_count : IP2HC_TABLE_SIZE;
}

// Store session state for concurrent tcp connections
register session_state {
    width : TCP_SESSION_STATE_WIDTH;
    instance_count : TCP_SESSION_TABLE_SIZE;
}

// Store session sequence number(SYN-ACK's) for concurrent tcp connections
register session_seq {
    width : 32;
    instance_count : TCP_SESSION_TABLE_SIZE;
}

// Temporary bitmap for storing  updated hop count value
register temporary_bitmap {
    width : TEMPORARY_BITMAP_WIDTH;
    instance_count : TEMPORARY_BITMAP_SIZE;
}

// Bitarray used to identify whether the cached entry is hot
register report_bitarray {
    width : 1;
    instance_count : IP2HC_TABLE_SIZE;
}

// The number of abnormal packet per period
counter mismatch_counter {
    type : packets;
    instance_count : 1;
}

// The number of missed packets
counter miss_counter {
    type : packets;
    instance_count : 1;
}

/*******************************************************************************
*****                     Match-Action Table Definition                   ******
*******************************************************************************/

// Tag the packet as normal
table tag_packet_normal_table {
    actions { tag_packet_normal; }
    max_size : 1;
}

action tag_packet_normal() {
    modify_field(meta.packet_tag, NORMAL_FLAG);
}

// Tag the packet as abnormal
table tag_packet_abnormal_table {
    actions { tag_packet_abnormal; }
    max_size : 1;
}

action tag_packet_abnormal() {
    modify_field(meta.packet_tag, ABNORMAL_FLAG);
}

// Used to get state(0:learning 1:filtering) of switch
// and judge whether the packet should be inspect by nethcf
table nethcf_enable_table {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions { enable_nethcf; }
    max_size : 2;
}

action enable_nethcf(nethcf_enable_flag) {
    modify_field(meta.nethcf_enable_flag, nethcf_enable_flag);
}

// Get the IP address used to match ip2hc_table
// For SYN/ACK packets, using dst IP address
// For other packets, using src IP address
table nethcf_prepare_table {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
    }
    actions {
        prepare_src_ip;
        prepare_dst_ip;
    }
    max_size : 2;
}

action prepare_src_ip() {
    register_read(meta.nethcf_state, nethcf_state, 0);
    modify_field(meta.ip_for_match, ipv4.srcAddr);
}

action prepare_dst_ip() {
    register_read(meta.nethcf_state, nethcf_state, 0);
    modify_field(meta.ip_for_match, ipv4.dstAddr);
}

// The ip2hc table, if the current packet hits the ip2hc table, action
// table_hit is executed, otherwise action table_miss is executed
table ip2hc_table {
    reads {
        meta.ip_for_match : ternary;
    }
    actions {
        table_miss;
        table_hit;
    }
    max_size : IP2HC_TABLE_SIZE;
}

action table_miss() {
    count(miss_counter, 0);
    modify_field(meta.ip2hc_hit_flag, 0);
}

action table_hit(index, hop_count) {
    modify_field(meta.ip2hc_index, index);
    modify_field(meta.ip2hc_hop_count, hop_count);
    modify_field(meta.ip2hc_hit_flag, 1);
}

// Get packets' tcp session information. Notice: dual direction packets in one
// flow should belong to same tcp session and use same hash value
table session_check_table {
    actions {
        check_tcp_session;
    }
    max_size : 1;
}

action check_tcp_session() {
    bit_xor(meta.src_dst_ip, ipv4.srcAddr, ipv4.dstAddr);
    bit_xor(meta.src_dst_port, tcp.srcPort, tcp.dstPort);
    modify_field_with_hash_based_offset(
        meta.tcp_session_index, 0,
        tcp_session_index_hash, TCP_SESSION_TABLE_SIZE
    );
    register_read(
        meta.tcp_session_state, session_state,
        meta.tcp_session_index
    );
    register_read(
        meta.tcp_session_seq, session_seq,
        meta.tcp_session_index
    );
    subtract(meta.ack_seq_diff, tcp.ackNo, meta.tcp_session_seq);
}

field_list_calculation tcp_session_index_hash {
    input {
        l3_hash_fields;
    }
    algorithm : crc16;
    output_width : TCP_SESSION_INDEX_WIDTH;
}

field_list l3_hash_fields {
    meta.src_dst_ip;
    ipv4.protocol;
    meta.src_dst_port;
}

// Mointor tcp session according to expected state transition
table session_monitor_table {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
        meta.ack_seq_diff : ternary;
        meta.tcp_session_state : ternary;
    }
    actions {
        monitor_session;
    }
    max_size : 10;
}

action monitor_session(session_monitor_result) {
    modify_field(meta.session_monitor_result, session_monitor_result);
}

// Someone is attempting to establish a connection from server
table session_init_table {
    actions {
        init_session;
    }
    max_size : 1;
}

action init_session() {
    register_write(session_state, meta.tcp_session_index, 1);
    register_write(session_seq, meta.tcp_session_index, tcp.seqNo);
}

// According to final TTL, select initial TTL and compute hop count
table hc_compute_table {
    reads {
        ipv4.ttl : range;
    }
    actions {
        compute_hc;
    }
    max_size : HC_COMPUTE_TABLE_SIZE;
}

action compute_hc(initial_ttl) {
    subtract(meta.packet_hop_count, initial_ttl, ipv4.ttl);
}

// Establish the connection, and update IP2HC
table session_complete_table {
    actions { complete_session; }
    max_size : 1;
}

action complete_session() {
    // Update tcp session state
    register_write(session_state, meta.tcp_session_index, 0);
}

table hc_update_table {
    actions { update_hc; }
}

action update_hc() {
    // Set IP2HC table entry to dirty
    set_entry_to_dirty();
    update_controller();
}

// When a session is complete on the switch, the switch will send
// a packet to controller to update ip2hc table on the controller
action update_controller() {
    //modify_field(ipv4.dstAddr, CONTROLLER_IP_ADDRESS);
    //modify_field(standard_metadata.egress_spec, CONTROLLER_PORT);
    modify_field(meta.update_ip2hc_flag, 1);
    clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
}

action set_entry_to_dirty() {
    register_write(ip2hc_valid_flag, meta.ip2hc_index, 1);
    // Store the new hop count into the dirty bitmap
    write_to_temporary_bitmap();
}

action write_to_temporary_bitmap() {
    // Compute the index value (row number) of temporary bitmap
    modify_field_with_hash_based_offset(
        meta.temporary_bitmap_index, 0,
        temporary_bitmap_index_hash, TEMPORARY_BITMAP_SIZE
    );
    // Read the row (bitarray) from the temporary bitmap
    register_read(
        meta.temporary_bitarray, temporary_bitmap, meta.temporary_bitmap_index
    );
    // Compute the corresponding bitarray according to new hop count of packets
    shift_left(meta.hop_count_bitarray, 1, meta.packet_hop_count);
    // Compute the new row
    bit_or(
        meta.temporary_bitarray,
        meta.temporary_bitarray, meta.hop_count_bitarray
    );
    // Write the new row back to temporary bitmap
    register_write(
        temporary_bitmap, meta.temporary_bitmap_index, meta.temporary_bitarray
    );
}

field_list_calculation temporary_bitmap_index_hash {
    input { temporary_bitmap_index_hash_fields; }
    algorithm : crc16;
    output_width : TEMPORARY_BITMAP_INDEX_WIDTH;
}

field_list temporary_bitmap_index_hash_fields {
    meta.ip_for_match;
}

// Except for HC computing, check whether the ip2hc item is dirty
table hc_inspect_table {
    reads {
        ipv4.ttl : range;
    }
    actions { 
        inspect_hc;
    }
    max_size : HC_COMPUTE_TABLE_SIZE;
}

action inspect_hc(initial_ttl) {
    subtract(meta.packet_hop_count, initial_ttl, ipv4.ttl);
    register_read(meta.ip2hc_valid_flag, ip2hc_valid_flag, meta.ip2hc_index);
    read_from_temporary_bitmap();
}

action read_from_temporary_bitmap() {
    // Compute the index value (row number) of temporary bitmap
    modify_field_with_hash_based_offset(
        meta.temporary_bitmap_index, 0,
        temporary_bitmap_index_hash, TEMPORARY_BITMAP_SIZE
    );
    // Read the row (bitarray) from the temporary bitmap
    register_read(
        meta.temporary_bitarray, temporary_bitmap, meta.temporary_bitmap_index
    );
    shift_right(
        meta.temporary_bitarray, meta.temporary_bitarray, meta.packet_hop_count
    );
    bit_and(meta.dirty_hc_hit_flag, meta.temporary_bitarray, 1);
}

// Update ip2hc_counter
table ip2hc_counter_update_table {
    actions { update_ip2hc_counter; }
    max_size : 1;
}

action update_ip2hc_counter() {
    register_read(meta.ip2hc_counter_value, ip2hc_counter, meta.ip2hc_index);
    add_to_field(meta.ip2hc_counter_value, 1);
    register_write(ip2hc_counter, meta.ip2hc_index, meta.ip2hc_counter_value);
}

// Set report_bitarray
table report_bitarray_set_table {
    actions { set_report_bitarray; }
    max_size : 1;
}

action set_report_bitarray() {
    register_write(report_bitarray, meta.ip2hc_index, 1);
}

// If the packet is judged as abnormal because its suspected hop-count,
// handle it according to the nethcf state.
// For learning state, just update mismatch_counter
// For filtering state, every abnormal packets should be dropped and
// mismatch_counter should be updated as well
table process_mismatch_at_learning_table {
    actions {
        process_mismatch_at_learning;
    }
    max_size : 1;
}

action process_mismatch_at_learning() {
    count(mismatch_counter, 0);
}

table process_mismatch_at_filtering_table {
    actions {
        process_mismatch_at_filtering;
    }
    max_size : 1;
}

action process_mismatch_at_filtering() {
    count(mismatch_counter, 0);
    tag_packet_abnormal();
}

// When a packet is missed, clone it to controller and pass it at learning state
table process_miss_at_learning_table {
    actions { process_miss_at_learning; }
    max_size : 1;
}

action process_miss_at_learning() {
    clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
}

field_list meta_data_for_clone {
    standard_metadata;
    meta;
}

// When a packet is missed, direct it to controller at filtering state
table process_miss_at_filtering_table {
    actions { process_miss_at_filtering; }
    max_size : 1;
}

action process_miss_at_filtering() {
    clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
    tag_packet_abnormal();
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
    max_size : FORWARD_TABLE_SIZE;
}

action _drop() {
    drop();
}

// For the final ack packet of handshaking, change the dst ip to tell controller
// this is a hop count update message
table process_hc_update_table {
    actions { process_hc_update; }
    max_size : 1;
}

action process_hc_update() {
    modify_field(ipv4.dstAddr, CONTROLLER_IP_ADDRESS);
    truncate(PACKET_TRUNCATE_LENGTH);
}

// At learning state, for the cloned missed packet which should be sent to
// controller, truncate it to only send digest to the controller
table process_cloned_miss_at_learning_table {
    actions { process_cloned_miss_at_learning; }
    max_size : 1;
}

action process_cloned_miss_at_learning() {
    truncate(PACKET_TRUNCATE_LENGTH);
}

// At filtering state, for the cloned missed packet which should be sent to
// controller, direct the whole packet to the controller
table process_cloned_miss_at_filtering_table {
    actions { process_cloned_miss_at_filtering; }
    max_size : 1;
}

action process_cloned_miss_at_filtering() {
}

/*******************************************************************************
*****                        Control Flow Definition                      ******
*******************************************************************************/

control ingress {
    // Tag all packets as normal first
    apply(tag_packet_normal_table);
    // Check whether NetHCF is enabled
    apply(nethcf_enable_table);
    if (meta.nethcf_enable_flag == 1) {
        // Get ip address used to match the IP2HC mapping table
        apply(nethcf_prepare_table);
        // Match the IP2HC mapping table
        apply(ip2hc_table);
        if (meta.ip2hc_hit_flag == 1) {
            // IP is cached in IP2HC
            apply(session_check_table);
            apply(session_monitor_table);
            if (meta.session_monitor_result == SESSION_MONITOR_INIT) {
                // Received SYN/ACK packet, need to init TCP session
                apply(session_init_table);
            }
            else if (meta.session_monitor_result == SESSION_MONITOR_UPDATE) {
                // Legal connection established, compute the hop count value and
                // updates the ip2hc table on the switch and controller
                apply(hc_compute_table);
                apply(session_complete_table);
                if (meta.packet_hop_count != meta.ip2hc_hop_count) {
                    apply(hc_update_table);
                }
            }
            else if (meta.session_monitor_result == SESSION_MONITOR_ABNORMAL) {
                // Illegal connection attempt
                apply(tag_packet_abnormal_table);
            }
            else {
                // Packets pass TCP session monitoring, compute packet's hop
                // count and refer to its original hop count
                apply(hc_inspect_table);
                if ((meta.packet_hop_count == meta.ip2hc_hop_count) or
                   ((meta.ip2hc_valid_flag & meta.dirty_hc_hit_flag) == 1)) {
                    // It is normal
                    // Only update hit count when the packet is legal
                    apply(ip2hc_counter_update_table);
                    if (meta.ip2hc_counter_value > IP2HC_HOT_THRESHOLD) {
                        apply(report_bitarray_set_table);
                    }
                }
                else {
                    // Suspicious packets with mismatched hop count value
                    if (meta.nethcf_state == LEARNING_STATE) {
                        apply(process_mismatch_at_learning_table);
                    }
                    else {
                        apply(process_mismatch_at_filtering_table);
                    }
                }
            }
        }
        else {
            // IP is not cached in IP2HC
            if (meta.nethcf_state == LEARNING_STATE) {
                apply(process_miss_at_learning_table);
            }
            else {
                apply(process_miss_at_filtering_table);
            }
        }
    }
    // Drop abnormal packets and forward normal packets in layer two
    apply(l2_forward_table);
}

control egress {
    // Judging whether to send a header or a whole packet
    if (standard_metadata.egress_port == CONTROLLER_PORT) {
        if (meta.update_ip2hc_flag == 1) {
            apply(process_hc_update_table);
        }
        else if (meta.nethcf_state == LEARNING_STATE) {
            apply(process_cloned_miss_at_learning_table);
        }
        else if (meta.nethcf_state == FILTERING_STATE) {
            apply(process_cloned_miss_at_filtering_table);
        }
    }
}
