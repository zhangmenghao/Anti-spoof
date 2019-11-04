/*******************************************************************************
    > File Name: nethcf.p4
    > Author: Guanyu Li & Xiao Kong
    > Mail: dracula.guanyu.li@gmail.com & kongxiao0532@gmail.com
    > Created Time: Fri 11 May 2018 9:12:19 AM CST
******************************************************************************/

#include "includes/headers.p4"
#include "includes/parser.p4"
#include <tofino/intrinsic_metadata.p4>
#include <tofino/stateful_alu_blackbox.p4>
#include <tofino/constants.p4>

/* Width setting */
#define HOP_COUNT_WIDTH 8
#define IP2HC_INDEX_WIDTH 23
#define IP2HC_COUNTER_WIDTH 8
#define TEMPORARY_BITMAP_WIDTH 1
#define TEMPORARY_BITMAP_INDEX_WIDTH 9
#define SEQ_NO_WIDTH 32
#define SESSION_INDEX_WIDTH 8
#define SESSION_TABLE_SIZE 256 // 2^8
#define SESSION_STATE_WIDTH 2
#define SESSION_MONITOR_RESULT_WIDTH 3
#define PACKET_TAG_WIDTH 2

/* Size setting */
#define NETHCF_ENABLE_TABLE_SIZE 1
#define NETHCF_PREPARE_TABLE_SIZE 1
#define HC_INSPECT_TABLE_SIZE 8
/* #define IP2HC_TABLE_SIZE 65536 // 2^16 */
#define IP2HC_TABLE_SIZE 13
// #define TEMPORARY_BITMAP_SIZE 16
// #define TEMPORARY_BITMAP_ARRAY_SIZE 16
#define TEMPORARY_BITMAP_SIZE 512 /* 16 * 32* */
#define TEMPORARY_BITMAP_ARRAY_SIZE 1
#define FORWARD_TABLE_SIZE 10
#define ONE_ACTION_TABLE_SIZE 0

/* Specific value setting */
#define CLONE_SPEC_VALUE 250
#define CONTROLLER_IP_ADDRESS 0xC0A83865 //192.168.56.101
#define CONTROLLER_PORT 3 // Maybe this parameter can be stored in a register
#define PACKET_TRUNCATE_LENGTH 54
#define IP2HC_HOT_THRESHOLD 10

/* States of NetHCF */
#define LEARNING_STATE 0
#define FILTERING_STATE 1

/* Flag of packets */
#define NORMAL_FLAG 0
#define ABNORMAL_FLAG 1
#define REPLY_SA_FLAG 2
#define REPLY_RST_FLAG 3

/* States of TCP session monitor */
#define SESSION_INITIAL 0
#define HANDSHAKE_START 1
#define SYN_COOKIE_START 2
#define SYN_COOKIE_FINISH 3

/* Results of TCP Proxy */
#define PASS_TO_MONITOR 0
#define PROXY_REPLY_SYN_ACK 1
#define PROXY_REPLY_RST 2
#define PROXY_ABNORMAL 3

/* Results of TCP session monitor */
#define PASS_AND_NOP 0
#define FIRST_SYN 1
#define SYNACK_WITHOUT_PROXY 2
#define ACK_WITHOUT_PROXY 3
#define ACK_WITH_PROXY 4
#define SYN_AFTER_PROXY 5
#define MONITOR_ABNORMAL 6

/*******************************************************************************
*****                       Metadata Definition                           ******
*******************************************************************************/

header_type meta_t {
    fields {
        /* Metadata about HCF */
        nethcf_enable_flag : 1; // 0: Not Inspected 1: Inspected
        nethcf_state : 1; // 0: Learning 1: Filtering
        packet_hop_count : HOP_COUNT_WIDTH; // Hop Count of this packet
        ip_for_match : 32; // IP address for searching the IP2HC table
        ip2hc_index : IP2HC_INDEX_WIDTH;
        ip2hc_hit_flag : 1; // 0: Not Hit 1 : Hit
        ip2hc_hop_count : HOP_COUNT_WIDTH; // Hop Count in IP2HC table
        ip2hc_counter_value : IP2HC_COUNTER_WIDTH; // Counter of IP2HC table
        ip2hc_valid_flag : 1; // Whether corresponding IP2HC item is dirty
        dirty_hc_hit_flag : 1; // Whether Hop Count exists in temporary bitmap
        temporary_bitmap_index : TEMPORARY_BITMAP_INDEX_WIDTH;
        temporary_bitarray : TEMPORARY_BITMAP_WIDTH;
        // hop_count_bitarray : TEMPORARY_BITMAP_WIDTH;
        update_ip2hc_flag : 1; // Whether need to update IP2HC in cache
        /* Metadata about session monitor */
        /* Proxy module */
        session_index : SESSION_INDEX_WIDTH;
        calculated_syn_cookie : SEQ_NO_WIDTH;
        seq_no_diff : SEQ_NO_WIDTH;
        tcp_syn_ack : 2;
        proxy_session_state : SESSION_STATE_WIDTH;
        session_proxy_result : SESSION_MONITOR_RESULT_WIDTH;
        /* Monitor module */
        monitor_session_state : SESSION_STATE_WIDTH;
        session_seq : 32; // sequence number of SYN-ACK packet
        session_monitor_result : SESSION_MONITOR_RESULT_WIDTH;
        ack_seq_diff : 32;
        /* Other metadata */
        packet_tag : PACKET_TAG_WIDTH; // 0: Normal 1: Abnormal
        src_dst_ip : 32; // Used to compute tcp session index or change src/dst
        src_dst_port : 16; // Used to compute tcp session index or change srcdst
        src_dst_mac : 48; // Used to exchange src and dst mac address
    }
}

metadata meta_t meta;

/*******************************************************************************
*****                 Register and Counter Definition               ******
*******************************************************************************/

// The state of the switch, maintained by CPU(control.py)
register r_nethcf_state {
    width : 1;
    instance_count : 1;
}

// Save the hit count value of each entry in IP2HC table
register r_ip2hc_counter {
    width : IP2HC_COUNTER_WIDTH;
    instance_count : IP2HC_TABLE_SIZE;
}

// The flag bit array of IP2HC to identify whether the IP2HC iterm is dirty
register r_ip2hc_valid_flag {
    width : 1;
    instance_count : IP2HC_TABLE_SIZE;
}

// Temporary bitmap for storing  updated Hop Count value
register r_temporary_bitmap {
    width : TEMPORARY_BITMAP_WIDTH;
    instance_count : TEMPORARY_BITMAP_SIZE;
}

// Bitarray used to identify whether the IP2HC entry is hot
register r_report_bitarray {
    width : 1;
    instance_count : IP2HC_TABLE_SIZE;
}

// Store session state for concurrent tcp connections
register r_proxy_session_state {
    width : SESSION_STATE_WIDTH;
    instance_count : SESSION_TABLE_SIZE;
}

// Store session state for concurrent tcp connections
register r_monitor_session_state {
    width : SESSION_STATE_WIDTH;
    instance_count : SESSION_TABLE_SIZE;
}

// Store session sequence number(SYN-ACK's) for concurrent tcp connections
register r_session_seq {
    width : 32;
    instance_count : SESSION_TABLE_SIZE;
}

// The number of abnormal packet per period
counter r_mismatch_counter {
    type : packets;
    instance_count : 1;
}

// The number of missed packets
counter r_miss_counter {
    type : packets;
    instance_count : 1;
}

/*******************************************************************************
*****                     Match-Action Table Definition                   ******
*******************************************************************************/

// Tag the packet as normal
table tag_packet_normal_table {
    actions {
        tag_packet_normal;
    }
    default_action : tag_packet_normal();
    size : ONE_ACTION_TABLE_SIZE;
}

action tag_packet_normal() {
    modify_field(meta.packet_tag, NORMAL_FLAG);
}

// Tag the packet as abnormal
table tag_packet_abnormal_table {
    actions {
        tag_packet_abnormal;
    }
    default_action : tag_packet_abnormal();
    size : ONE_ACTION_TABLE_SIZE;
}

action tag_packet_abnormal() {
    modify_field(meta.packet_tag, ABNORMAL_FLAG);
}

// Used to get state(0:learning 1:filtering) of switch
// and judge whether the packet should be inspect by nethcf
table nethcf_enable_table {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        enable_nethcf;
    }
    default_action : enable_nethcf(1);
    size : NETHCF_ENABLE_TABLE_SIZE;
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
    default_action : prepare_src_ip();
    size : NETHCF_PREPARE_TABLE_SIZE;
}

blackbox stateful_alu s_read_r_nethcf_state{
    reg : r_nethcf_state;
    update_lo_1_value : register_lo;

    output_value : alu_lo;
    output_dst : meta.nethcf_state;
}
action prepare_src_ip() {
    s_read_r_nethcf_state.execute_stateful_alu(0);
    modify_field(meta.ip_for_match, ipv4.srcAddr);
}

action prepare_dst_ip() {
    s_read_r_nethcf_state.execute_stateful_alu(0);
    modify_field(meta.ip_for_match, ipv4.dstAddr);
}

// The IP2HC table, if the current packet hits the IP2HC table, action
// table_hit is executed, otherwise action table_miss is executed
table ip2hc_table {
    reads {
        meta.ip_for_match : ternary;
    }
    actions {
        table_miss;
        table_hit;
    }
    default_action : table_miss();
    size : IP2HC_TABLE_SIZE;
}

action table_miss() {
    count(r_miss_counter, 0);
    modify_field(meta.ip2hc_hit_flag, 0);
}

action table_hit(index, hop_count) {
    modify_field(meta.ip2hc_index, index);
    modify_field(meta.ip2hc_hop_count, hop_count);
    modify_field(meta.ip2hc_hit_flag, 1);
}

// According to final TTL, select initial TTL and compute Hop Count
table hc_inspect_table {
    reads {
        ipv4.ttl : range;
    }
    actions {
        inspect_hc;
    }
    default_action : inspect_hc(255);
    size : HC_INSPECT_TABLE_SIZE;
}

action inspect_hc(initial_ttl) {
    subtract(meta.packet_hop_count, initial_ttl, ipv4.ttl);
}

// Update r_ip2hc_counter
table ip2hc_counter_update_table {
    actions {
        update_ip2hc_counter;
    }
    default_action : update_ip2hc_counter();
    size : ONE_ACTION_TABLE_SIZE;
}

// read r_ip2hc_counter, increment by 1
// then write back and output the value into meta.ip2hc_counter_value
blackbox stateful_alu s_update_ip2hc_counter{
    reg : r_ip2hc_counter;
    update_lo_1_value : register_lo + 1;

    output_value : alu_lo;
    output_dst : meta.ip2hc_counter_value;
}
action update_ip2hc_counter() {
    s_update_ip2hc_counter.execute_stateful_alu(meta.ip2hc_index);
}

table calculate_session_table_index_table {
    actions {
        calculate_session_table_index;
    }
    default_action : calculate_session_table_index();
    size : ONE_ACTION_TABLE_SIZE;
}
action calculate_session_table_index() {
    bit_xor(meta.src_dst_ip, ipv4.srcAddr, ipv4.dstAddr);
    bit_xor(meta.src_dst_port, tcp.srcPort, tcp.dstPort);
    modify_field_with_hash_based_offset(
        meta.session_index, 0,
        session_index_hash, SESSION_TABLE_SIZE
    );
}

// Calculate SYN cookie value
table calculate_cookie_seqno_table {
    actions {
        calculate_cookie_seqno;
    }
    default_action : calculate_cookie_seqno();
    size : ONE_ACTION_TABLE_SIZE;
}
action calculate_cookie_seqno() {
    modify_field_with_hash_based_offset(
        meta.calculated_syn_cookie, 0,
        syn_cookie_hash, 0x100000000 /* 2^32 */);
    );
}
field_list_calculation syn_cookie_hash {
    input {
        symmetry_hash_fields;
    }
    algorithm : csum16;
    output_width : SEQ_NO_WIDTH;
}
field_list symmetry_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
}

// Calculate its difference with the actual one
table calculate_seqno_diff_table {
    actions {
        calculate_seqno_diff;
    }
    default_action : calculate_seqno_diff();
    size : ONE_ACTION_TABLE_SIZE;
}
action calculate_seqno_diff() {
    subtract(meta.seq_no_diff, tcp.ackNo, meta.calculated_syn_cookie);
}

table prepare_tcp_flags_as_real_table {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
        meta.seq_no_diff : ternary;
        /* STATIC ENTRIES
         * 1 0 0&&&0 -> 2
         * 0 1 1&&&1 -> 1
         * 1 0 0&&&0 -> 2
         * else      -> 3
         */
    }
    actions {
        prepare_tcp_flags_as_real;
    }
    default_action : prepare_tcp_flags_as_real(3);
    size : ONE_ACTION_TABLE_SIZE;
}
action prepare_tcp_flags_as_real(real_num) {
    modify_field(meta.tcp_syn_ack, real_num);
}

// Update register r_proxy_session_state
table update_proxy_session_state_table {
    actions {
        update_proxy_session_state;
    }
    default_action : update_proxy_session_state();
    size : ONE_ACTION_TABLE_SIZE;
}
blackbox stateful_alu s_update_proxy_session_state {
    reg : r_proxy_session_state;
    /* A Tricky Implementation
     * Use a table to combine SYN+ACK information into a number
     *  SYNACK  STATE   SUM     ->     STATE
     *    10      0      2             1(0+1)(PREDICATE_1)
     *    01      1      2             2(1+1)(PREDICATE_1)
     *    10      2      4                0  (PREDICATE_2)
     */
    condition_lo : meta.tcp_syn_ack + register_lo;
	update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo + 1;    // STATE_0->STATE_1 or STATE_1->STATE_2
	update_lo_2_predicate: not condition_lo;
	update_lo_2_value : 0;  // STATE_2->STATE_0

    output_value : register_lo;
    output_dst : meta.proxy_session_state;
}
action update_proxy_session_state() {
    s_update_proxy_session_state.execute_stateful_alu(meta.session_index);
}

table session_proxy_table {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
        meta.seq_no_diff : ternary;
        meta.proxy_session_state : ternary;
        /* STATIC ENTRIES
         * 1 0 0&&&0 0 -> 2 Reply: SYN+ACK            (Priority 1)
         * 0 1 1&&&1 1 -> 3 Reply: RST                (Priority 1)
         * 1 0 0&&&0 2 -> 0 Tag: Proceed to Monitor   (Priority 1)
         * 0 1 0&&&0 2 -> 1 Tag: ABNORMAL             (Priority 1)
         * 0 1 0&&&0 1 -> 1 Tag: ABNORMAL             (Priority 0)
         * else        -> 0 Tag: Proceed to Monitor   (Priority 0)
         */
    }
    actions {
        proxy_session;
    }
    default_action : monitor_session(0);
    size : 10;
}
action proxy_session(tag) {
    modify_field(meta.packet_tag, tag);
}

// Get packets' tcp session information. Notice: dual direction packets in one
// flow should belong to same tcp session and use same hash value
// NOTICE
// session_monitor_prepare_table has to be split into 3 seperate tables
// to run serial instructions

table session_monitor_prepare_table_2 {
    actions {
        prepare_for_session_monitor_2;
    }
    default_action : prepare_for_session_monitor_2();
    size : ONE_ACTION_TABLE_SIZE;
}
blackbox stateful_alu s_read_session_state{
    reg : r_session_state;
    update_lo_1_value : register_lo;

    output_value : alu_lo;
    output_dst : meta.session_state;
}
blackbox stateful_alu s_read_session_seq{
    reg : r_session_seq;
    update_lo_1_value : register_lo;

    output_value : alu_lo;
    output_dst : meta.session_seq;
}
action prepare_for_session_monitor_2() {
    s_read_session_state.execute_stateful_alu(meta.session_index);
    s_read_session_seq.execute_stateful_alu(meta.session_index);
}

table session_monitor_prepare_table_3 {
    actions {
        prepare_for_session_monitor_3;
    }
    default_action : prepare_for_session_monitor_3();
    size : ONE_ACTION_TABLE_SIZE;
}
action prepare_for_session_monitor_3() {
    subtract(meta.ack_seq_diff, tcp.ackNo, meta.session_seq);
}

field_list_calculation session_index_hash {
    input {
        l3_hash_fields;
    }
    algorithm : crc16;
    output_width : SESSION_INDEX_WIDTH;
}

field_list l3_hash_fields {
    meta.src_dst_ip;
    ipv4.protocol;
    // meta.src_dst_port;
}

// Mointor tcp session according to expected state transition
table session_monitor_table {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
        meta.ack_seq_diff : ternary;
        meta.session_state : ternary;
    }
    actions {
        monitor_session;
    }
    default_action : monitor_session(0);
    size : 10;
}

action monitor_session(session_monitor_result) {
    modify_field(meta.session_monitor_result, session_monitor_result);
    // Debuging
    // modify_field(ipv4.ttl, meta.session_index);
}

// Receive the first SYN packet, employ SYN Cookie to defend
table syn_cookie_init_table {
    actions {
        init_syn_cookie;
    }
    default_action : init_syn_cookie();
    size : ONE_ACTION_TABLE_SIZE;
}

action init_syn_cookie() {
    // Return SYN/ACK
    modify_field(tcp.syn, 1);
    modify_field(tcp.ack, 1);
    add(tcp.ackNo, tcp.seqNo, 1);
    // We use "session index" as cookie currently
    modify_field(tcp.seqNo, meta.session_index);
    // Exchange src and dst mac address
    swap(ethernet.srcAddr, ethernet.dstAddr);
    // Exchange src and dst ip address
    swap(ipv4.srcAddr, ipv4.dstAddr);
    // Exchange src and dst port
    swap(tcp.srcPort, tcp.dstPort);
    // Store SYN Cookie into r_session_seq register array
    register_write(r_session_seq, meta.session_index, tcp.seqNo);
    // Update session state
    register_write(r_session_state, meta.session_index, SYN_COOKIE_START);
    // Tag the packet to forward it back
    modify_field(meta.packet_tag, SYN_COOKIE_FLAG);
}

// Someone is attempting to establish a connection from server
table session_init_table {
    actions {
        init_session;
    }
    default_action : init_session();
    size : ONE_ACTION_TABLE_SIZE;
}

action init_session() {
    register_write(r_session_state, meta.session_index, HANDSHAKE_START);
    register_write(r_session_seq, meta.session_index, tcp.seqNo);
}

// Establish the connection, and update IP2HC
table session_complete_table {
    actions {
        complete_session;
    }
    default_action : complete_session();
    size : ONE_ACTION_TABLE_SIZE;
}

action complete_session() {
    // Update tcp session state
    register_write(r_session_state, meta.session_index, SESSION_INITIAL);
}

// Update Hop Count at switch and controller
table hc_update_table {
    actions {
        update_hc;
    }
    default_action : update_hc();
    size : ONE_ACTION_TABLE_SIZE;
}

action update_hc() {
    // Set IP2HC table entry to dirty
    set_entry_to_dirty();
    update_controller();
}

action set_entry_to_dirty() {
    register_write(r_ip2hc_valid_flag, meta.ip2hc_index, 1);
    // Store the new Hop Count into the dirty bitmap
    write_to_temporary_bitmap();
}

blackbox stateful_alu s_set_temporary_bitmap{
    reg : r_temporary_bitmap;
    update_lo_1_value : 1;

    output_value : alu_lo;
}
action write_to_temporary_bitmap() {
    /****************************************************
     * TOFINO: use a simple version of bitmap instead
     * An array instead of a bitmap (length of TEMPORARY_BITMAP_SIZE * TEMPORARY_BITMAP_ARRAY_SIZE)
     * one bit per row
     * may bring some hash collisions though ...
     ****************************************************/
    s_set_temporary_bitmap.execute_stateful_alu_from_hash(temporary_bitmap_index_hash);
    /*************************************************************************
     * OLD bmv2 version
    // Compute the index value (row number) of temporary bitmap
    modify_field_with_hash_based_offset(
        meta.temporary_bitmap_index, 0,
        temporary_bitmap_index_hash, TEMPORARY_BITMAP_SIZE
    );
    // Read the row (bitarray) from the temporary bitmap
    register_read(
        meta.temporary_bitarray, r_temporary_bitmap, meta.temporary_bitmap_index
    );
    // Compute the corresponding bitarray according to new Hop Count of packets
    shift_left(meta.hop_count_bitarray, 1, meta.packet_hop_count);
    // Compute the new row
    bit_or(
        meta.temporary_bitarray,
        meta.temporary_bitarray, meta.hop_count_bitarray
    );
    // Write the new row back to temporary bitmap
    register_write(
        r_temporary_bitmap, meta.temporary_bitmap_index, meta.temporary_bitarray
    );
     **************************************************************************/
}

field_list_calculation temporary_bitmap_index_hash {
    input { temporary_bitmap_index_hash_fields; }
    algorithm : crc16;
    output_width : TEMPORARY_BITMAP_INDEX_WIDTH;
}

field_list temporary_bitmap_index_hash_fields {
    meta.ip_for_match;
    meta.packet_hop_count;
}

// When a session is complete on the switch, the switch will send
// a packet to controller to update IP2HC table on the controller
action update_controller() {
    //modify_field(ipv4.dstAddr, CONTROLLER_IP_ADDRESS);
    //modify_field(eg_intr_md.egress_port, CONTROLLER_PORT);
    modify_field(meta.update_ip2hc_flag, 1);
    clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
}

// This connection pass SYN Cookie check, let the client reconnect
table syn_cookie_complete_table {
    actions {
        complete_syn_cookie;
    }
    default_action : complete_syn_cookie();
    size : ONE_ACTION_TABLE_SIZE;
}

action complete_syn_cookie() {
    // Return RST packet
    modify_field(tcp.ack, 0);
    modify_field(tcp.psh, 0);
    modify_field(tcp.rst, 1);
    add(tcp.seqNo, meta.session_seq, 1);
    modify_field(tcp.ackNo, 0);
    // Exchange src and dst mac address
    swap(ethernet.srcAddr, ethernet.dstAddr);
    // Exchange src and dst ip address
    swap(ipv4.srcAddr, ipv4.dstAddr);
    // Exchange src and dst port
    swap(tcp.srcPort, tcp.dstPort);
    // Update session state
    register_write(r_session_state, meta.session_index, SYN_COOKIE_FINISH);
    // Tag the packet to forward it back
    modify_field(meta.packet_tag, SYN_COOKIE_FLAG);
}

// Pass SYN Cookie inspection, and restart session monitor like learning state
table session_monitor_restart_table {
    actions {
        restart_session_monitor;
    }
    default_action : restart_session_monitor();
    size : ONE_ACTION_TABLE_SIZE;
}

action restart_session_monitor() {
    // Reset session state
    register_write(r_session_state, meta.session_index, SESSION_INITIAL);
}

// Except for HC computing, check whether the IP2HC item is dirty
table hc_reinspect_table {
    actions {
        reinspect_hc;
    }
    default_action : reinspect_hc();
    size : ONE_ACTION_TABLE_SIZE;
}

action reinspect_hc() {
    //TODO: may needs to merge
    register_read(meta.ip2hc_valid_flag, r_ip2hc_valid_flag, meta.ip2hc_index);
    read_from_temporary_bitmap();
}

blackbox stateful_alu s_read_temporary_bitmap{
    reg : r_temporary_bitmap;
    update_lo_1_value : register_lo;

    output_value : register_lo;
    output_dst : meta.dirty_hc_hit_flag;
}
action read_from_temporary_bitmap() {
    /****************************************************
     * TOFINO: use a simple version of bitmap instead
     * An array instead of a bitmap (length of TEMPORARY_BITMAP_SIZE * TEMPORARY_BITMAP_ARRAY_SIZE)
     * one bit per row
     * may bring some hash collisions though ...
     ****************************************************/
    s_read_temporary_bitmap.execute_stateful_alu_from_hash(temporary_bitmap_index_hash);
    /*************************************************************************
     * OLD bmv2 version
    s_set_temporary_bitmap.execute_stateful_alu_from_hash(temporary_bitmap_index_hash);
    // Compute the index value (row number) of temporary bitmap
    modify_field_with_hash_based_offset(
        meta.temporary_bitmap_index, 0,
        temporary_bitmap_index_hash, TEMPORARY_BITMAP_SIZE
    );
    // Read the row (bitarray) from the temporary bitmap
    register_read(
        meta.temporary_bitarray, r_temporary_bitmap, meta.temporary_bitmap_index
    );
    shift_right(
        meta.temporary_bitarray, meta.temporary_bitarray, meta.packet_hop_count
    );
    bit_and(meta.dirty_hc_hit_flag, meta.temporary_bitarray, 1);
     **************************************************************************/
}

// Set r_report_bitarray
table report_bitarray_set_table {
    actions {
        set_report_bitarray;
    }
    default_action : set_report_bitarray();
    size : ONE_ACTION_TABLE_SIZE;
}

action set_report_bitarray() {
    register_write(r_report_bitarray, meta.ip2hc_index, 1);
}

// If the packet is judged as abnormal because its suspected hop-count,
// handle it according to the nethcf state.
// For learning state, just update r_mismatch_counter
// For filtering state, every abnormal packets should be dropped and
// r_mismatch_counter should be updated as well
table process_mismatch_at_learning_table {
    actions {
        process_mismatch_at_learning;
    }
    default_action : process_mismatch_at_learning();
    size : ONE_ACTION_TABLE_SIZE;
}

action process_mismatch_at_learning() {
    count(r_mismatch_counter, 0);
}

table process_mismatch_at_filtering_table {
    actions {
        process_mismatch_at_filtering;
    }
    default_action : process_mismatch_at_filtering();
    size : ONE_ACTION_TABLE_SIZE;
}

action process_mismatch_at_filtering() {
    count(r_mismatch_counter, 0);
    tag_packet_abnormal();
}

// When a packet is missed, clone it to controller and pass it at learning state
table process_miss_at_learning_table {
    actions {
        process_miss_at_learning;
    }
    default_action : process_miss_at_learning();
    size : ONE_ACTION_TABLE_SIZE;
}

action process_miss_at_learning() {
    clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
}

field_list meta_data_for_clone {
    ig_intr_md;
    meta;
}

// When a packet is missed, direct it to controller at filtering state
table process_miss_at_filtering_table {
    actions {
        process_miss_at_filtering;
    }
    default_action : process_miss_at_filtering();
    size : ONE_ACTION_TABLE_SIZE;
}

action process_miss_at_filtering() {
    clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
    tag_packet_abnormal();
}

// Forward table, now it just support layer 2
table l2_forward_table {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        _drop;
        forward_l2;
    }
    default_action : _drop();
    size : FORWARD_TABLE_SIZE;
}

action forward_l2(egress_port) {
    modify_field(eg_intr_md.egress_port, egress_port);
}

action _drop() {
    drop();
}

// Drop packet
table drop_table {
    actions {
        _drop;
    }
    size : ONE_ACTION_TABLE_SIZE;
}

// Forward back the packet
table back_forward_table {
    actions {
        forward_back;
    }
    default_action : forward_back();
    size : ONE_ACTION_TABLE_SIZE;
}

action forward_back() {
    modify_field(eg_intr_md.egress_port, ig_intr_md.ingress_port);
}

// For the final ack packet of handshaking, change the dst ip to tell controller
// this is a Hop Count update message
table process_hc_update_table {
    actions {
        process_hc_update;
    }
    default_action : process_hc_update();
    size : ONE_ACTION_TABLE_SIZE;
}

action process_hc_update() {
    modify_field(ipv4.dstAddr, CONTROLLER_IP_ADDRESS);
    truncate(PACKET_TRUNCATE_LENGTH);
}

// At learning state, for the cloned missed packet which should be sent to
// controller, truncate it to only send digest to the controller
table process_cloned_miss_at_learning_table {
    actions {
        process_cloned_miss_at_learning;
    }
    default_action : process_cloned_miss_at_learning();
    size : ONE_ACTION_TABLE_SIZE;
}

action process_cloned_miss_at_learning() {
    truncate(PACKET_TRUNCATE_LENGTH);
}

// At filtering state, for the cloned missed packet which should be sent to
// controller, direct the whole packet to the controller
table process_cloned_miss_at_filtering_table {
    actions {
        process_cloned_miss_at_filtering;
    }
    default_action : process_cloned_miss_at_filtering();
    size : ONE_ACTION_TABLE_SIZE;
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
        /* Stateful_alu : r_nethcf_state */
        apply(nethcf_prepare_table);
        // Match the IP2HC mapping table
        apply(ip2hc_table); //TODO: counter
        if (meta.ip2hc_hit_flag == 1) {
            // IP is cached in IP2HC
            apply(hc_inspect_table);
            if (meta.ip2hc_hop_count == meta.packet_hop_count) {
                // It is normal
                // Only update hit count when the Hop Count is correct
                /* Stateful_alu : r_ip2hc_counter */
                apply(ip2hc_counter_update_table);
            }
            else {
                // hop count does not match
                /*****************************************************
                 * TOFINO version -- register-oriented logic
                 * Split Proxy and Monitor apart
                 * 1. in filtering state (Proxy Module)
                 *  1) SYN + STATE_0 -> STATE_1 + Reply SYN+ACK
                 *  2) ACK + STATE_1 + right SEQ# -> STATE_2 + Reply RST
                 *  3) SYN + STATE_2 -> STATE_0 + Proceed to Moniter + tag
                 *  4) ACK + STATE_2 -> mark as ABNORMAL
                 *  5) ACK + STATE_1 + wrong SEQ# -> mark as ABNORMAL
                 *  6) OTHERS -> PASS to Monitor Module
                 * 2. Monitor Module
                 *  1) SYN + ACK + STATE_0 -> STATE_1 + store SEQ#
                 *  2) ACK + STATE_1 -> STATE_0 + right SEQ# -> update BITMAP + VALID_ARRAY
                 *  3) ACK + STATE_1 -> mark as ABNORMAL
                 *  4) OTHERS -> check BITMAP + VALID_ARRAY
                 ****************************************************/
                apply(calculate_session_table_index_table);
                if (meta.nethcf_state == FILTERING_STATE) {
                    /* PROXY
                     * register: r_proxy_session_state
                     *      SYN + STATE_0 -> STATE_1
                     *      ACK + STATE_1 + correct_SEQ# -> STATE_2
                     *      SYN + STATE_2 -> STATE_0
                     */
                    // calculate syn cookie
                    apply(calculate_cookie_seqno_table);
                    // calculate the difference between cookie and read SEQ#
                    apply(calculate_seqno_diff_table);
                    // Add another table to combine SYN+ACK information into a number
                    apply(prepare_tcp_flags_as_real_table);
                    // update register r_proxy_session_state
                    apply(update_proxy_session_state_table);
                    // Tag packets according to various senarios
                    apply(session_proxy_table);
                }
                if (meta.packet_tag == NORMAL_FLAG){
                    // MONITOR
                }


                // Operate tcp session monitoring
                /* Stateful_alu : r_session_state & r_session_seq */
                apply(session_monitor_prepare_table_2);
                apply(session_monitor_prepare_table_3);
                apply(session_monitor_table);
                if (meta.session_monitor_result == FIRST_SYN) {
                    if (meta.nethcf_state == FILTERING_STATE) {
                        // SYN Cookie is enabled to defend SYN DDoS at filtering
                        apply(syn_cookie_init_table);   //TODO: register_write * 2
                    }
                }
                else if (meta.session_monitor_result == SYNACK_WITHOUT_PROXY) {
                    // Received SYN/ACK packet, need to init TCP session
                    apply(session_init_table);  //TODO: register_write * 2
                }
                else if (meta.session_monitor_result == ACK_WITHOUT_PROXY) {
                    // Legal connection established, compute the Hop Count value
                    // and updates the IP2HC table on the switch and controller
                    apply(session_complete_table);  //TODO: register_write
                    apply(hc_update_table); //TODO: register_write * 2 and register_read
                }
                else if (meta.session_monitor_result == ACK_WITH_PROXY) {
                    apply(syn_cookie_complete_table);   //TODO: register_write
                }
                else if (meta.session_monitor_result == SYN_AFTER_PROXY) {
                    // The second syn which after SYN Cookie inspection
                    // Let this packet pass, and restart session monitor
                    apply(session_monitor_restart_table);  //TODO: register_write
                }
                else if (meta.session_monitor_result == MONITOR_ABNORMAL) {
                    // Illegal connection attempt
                    apply(tag_packet_abnormal_table);
                }
                else {
                    // Packets pass TCP session monitoring, compute packet's hop
                    // count and refer to its original Hop Count
                    apply(hc_reinspect_table);  //TODO: register_read * 2
                    if ((meta.ip2hc_valid_flag & meta.dirty_hc_hit_flag) == 1) {
                        // Only update hit count when the Hop Count is correct
                        apply(ip2hc_counter_update_table);  //TODO: Register_read and register_write
                    }
                    else {
                        // Suspicious packets with mismatched Hop Count value
                        if (meta.nethcf_state == LEARNING_STATE) {
                            apply(process_mismatch_at_learning_table);  //TODO: counter
                        }
                        else {
                            apply(process_mismatch_at_filtering_table); //TODO: counter
                        }
                   }
                }
            }
            // Hot IP2HC entry process
            if (meta.ip2hc_counter_value > IP2HC_HOT_THRESHOLD) {
                apply(report_bitarray_set_table);   //TODO: Register_write
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
    if (meta.packet_tag == NORMAL_FLAG) {
        // Normal packets
        apply(l2_forward_table);
    }
    else if (meta.packet_tag == ABNORMAL_FLAG) {
        // Abnormal packets
        apply(drop_table);
    }
    else {
        // Packets with SYN Cookie
        apply(back_forward_table);
    }
}

control egress {
    // Judging whether to send a header or a whole packet
    if (eg_intr_md.egress_port == CONTROLLER_PORT) {
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
