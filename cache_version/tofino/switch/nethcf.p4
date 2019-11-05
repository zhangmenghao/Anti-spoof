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
#define REPLY_SA_FLAG 1
#define REPLY_RST_FLAG 2
#define ABNORMAL_FLAG 3
#define PASS_AND_NOP 4
#define SAVE_TO_BITMAP 5

/* States of TCP session monitor */
#define SESSION_INITIAL 0
#define HANDSHAKE_START 1
#define SYN_COOKIE_START 2
#define SYN_COOKIE_FINISH 3

/* Results of TCP Proxy */
// #define PASS_TO_MONITOR 0
// #define PROXY_REPLY_SYN_ACK 1
// #define PROXY_REPLY_RST 2
// #define PROXY_ABNORMAL 3
/* Results of TCP session monitor */
// #define SYNACK_WITHOUT_PROXY 2
// #define ACK_WITHOUT_PROXY 3
// #define ACK_WITH_PROXY 4
// #define SYN_AFTER_PROXY 5
// #define MONITOR_ABNORMAL 6

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
        ip2hc_counter_update : 1;
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
register r_mismatch_counter {
    width : 32;
    instance_count : 1;
}

// The number of missed packets
register r_miss_counter {
    width : 32;
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

// blackbox stateful_alu s_read_r_nethcf_state{
//     reg : r_nethcf_state;
//     update_lo_1_value : register_lo;

//     output_value : alu_lo;
//     output_dst : meta.nethcf_state;
// }
action prepare_src_ip() {
    // s_read_r_nethcf_state.execute_stateful_alu(0);
    modify_field(meta.ip_for_match, ipv4.srcAddr);
}

action prepare_dst_ip() {
    // s_read_r_nethcf_state.execute_stateful_alu(0);
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
// blackbox stateful_alu s_update_miss_counter {
//     reg : r_miss_counter;
//     update_lo_1_value : register_lo;
// }
action table_miss() {
    // s_update_miss_counter.execute_stateful_alu(0);
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

table set_ip2hc_counter_update_table_1 {
    actions {
        set_ip2hc_counter_update_1;
    }
    default_action : set_ip2hc_counter_update_1();
    size : ONE_ACTION_TABLE_SIZE;
}
action set_ip2hc_counter_update_1() {
    modify_field(meta.ip2hc_counter_update, 1);
}

table calculate_session_table_index_table_1 {
    actions {
        calculate_session_table_index_1;
    }
    default_action : calculate_session_table_index_1();
    size : ONE_ACTION_TABLE_SIZE;
}
action calculate_session_table_index_1() {
    bit_xor(meta.src_dst_ip, ipv4.srcAddr, ipv4.dstAddr);
    bit_xor(meta.src_dst_port, tcp.srcPort, tcp.dstPort);
}
table calculate_session_table_index_table_2 {
    actions {
        calculate_session_table_index_2;
    }
    default_action : calculate_session_table_index_2();
    size : ONE_ACTION_TABLE_SIZE;
}
action calculate_session_table_index_2() {
    modify_field_with_hash_based_offset(
        meta.session_index, 0,
        session_index_hash, SESSION_TABLE_SIZE
    );
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
        syn_cookie_hash, 0x100000000 /* 2^32 */
    );
}
field_list_calculation syn_cookie_hash {
    input {
        symmetry_hash_fields;
    }
    algorithm : crc32;
    output_width : SEQ_NO_WIDTH;
}
field_list symmetry_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
}

// Calculate its difference with the actual one
table calculate_seqno_diff_table_1 {
    actions {
        calculate_seqno_diff_1;
    }
    default_action : calculate_seqno_diff_1();
    size : ONE_ACTION_TABLE_SIZE;
}
action calculate_seqno_diff_1() {
    subtract(meta.seq_no_diff, tcp.ackNo, meta.calculated_syn_cookie);
}

table prepare_tcp_flags_as_real_table_1 {
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
        prepare_tcp_flags_as_real_1;
    }
    default_action : prepare_tcp_flags_as_real_1(3);
    size : 4;
}
action prepare_tcp_flags_as_real_1(real_num) {
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
// blackbox stateful_alu s_update_proxy_session_state {
//     reg : r_proxy_session_state;
//     /* A Tricky Implementation
//      * Use a table to combine SYN+ACK information into a number
//      *  SYNACK  STATE   SUM     ->     STATE
//      *    10      0      2             1(0+1)(PREDICATE_1)
//      *    01      1      2             2(1+1)(PREDICATE_1)
//      *    10      2      4                0  (PREDICATE_2)
//      */
//     condition_lo : meta.tcp_syn_ack + register_lo == 2;
// 	update_lo_1_predicate : condition_lo;
//     update_lo_1_value : register_lo + 1;    // STATE_0->STATE_1 or STATE_1->STATE_2
// 	update_lo_2_predicate: not condition_lo;
// 	update_lo_2_value : 0;  // STATE_2->STATE_0

//     output_value : register_lo;
//     output_dst : meta.proxy_session_state;
// }
action update_proxy_session_state() {
    // s_update_proxy_session_state.execute_stateful_alu(meta.session_index);
}

table session_proxy_table {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
        meta.seq_no_diff : ternary;
        meta.proxy_session_state : ternary;
        /* STATIC ENTRIES
         * 1 0 0&&&0 0 -> 1 Reply: SYN+ACK            (Priority 1)
         * 0 1 1&&&1 1 -> 2 Reply: RST                (Priority 1)
         * 1 0 0&&&0 2 -> 0 Tag: Proceed to Monitor   (Priority 1)
         * 0 1 0&&&0 2 -> 3 Tag: ABNORMAL             (Priority 1)
         * 0 1 0&&&0 1 -> 3 Tag: ABNORMAL             (Priority 0)
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

table prepare_tcp_flags_as_real_table_2 {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
        /* STATIC ENTRIES
         * 0 1 -> 1
         * 1 1 -> 2
         * ELSE -> 0
         */
    }
    actions {
        prepare_tcp_flags_as_real_2;
    }
    default_action : prepare_tcp_flags_as_real_2(0);
    size : 4;
}
action prepare_tcp_flags_as_real_2(real_num) {
    modify_field(meta.tcp_syn_ack, real_num);
}

table update_session_seq_table {
    actions {
        update_session_seq;
    }
    default_action : update_session_seq();
    size : ONE_ACTION_TABLE_SIZE;
}
// blackbox stateful_alu s_update_session_seq{
//     reg : r_session_seq;
//     condition_lo : meta.tcp_syn_ack == 2 /* 1 1 */;
//     update_lo_1_predicate : condition_lo;
//     update_lo_1_value : tcp.seqNo;

//     output_value : alu_lo;
//     output_dst : meta.session_seq;
// }
action update_session_seq() {
    // s_update_session_seq.execute_stateful_alu(meta.session_index);
}

table calculate_seqno_diff_table_2 {
    actions {
        calculate_seqno_diff_2;
    }
    default_action : calculate_seqno_diff_2();
    size : ONE_ACTION_TABLE_SIZE;
}
action calculate_seqno_diff_2() {
    subtract(meta.seq_no_diff, tcp.ackNo, meta.session_seq);
}

// Update register r_monitor_session_state
table update_monitor_session_state_table {
    actions {
        update_monitor_session_state;
    }
    default_action : update_monitor_session_state();
    size : ONE_ACTION_TABLE_SIZE;
}
// blackbox stateful_alu s_update_monitor_session_state {
//     reg : r_monitor_session_state;
//     /* A Tricky Implementation
//      * Use a table to combine SYN+ACK information into a number
//      *  SYNACK     STATE   SUM SEQ#diff ->   STATE
//      *    11(2)      0      2     /      1(PREDICATE_1)
//      *    01(1)      1      2     1      0(PREDICATE_2)
//      */
//     condition_lo : meta.tcp_syn_ack + register_lo == 2;
//     condition_hi : meta.seq_no_diff == 1;

// 	update_lo_1_predicate : condition_lo;
//     update_lo_1_value : 1;
// 	update_lo_2_predicate: condition_hi and not condition_lo;
// 	update_lo_2_value : 0;

//     output_value : register_lo;
//     output_dst : meta.monitor_session_state;
// }
action update_monitor_session_state() {
    // s_update_monitor_session_state.execute_stateful_alu(meta.session_index);
}

table session_monitor_table {
    reads {
        tcp.syn : exact;
        tcp.ack : exact;
        meta.seq_no_diff : ternary;
        meta.monitor_session_state : ternary;
        /* STATIC ENTRIES UNFINISHED
         * 1 1 0&&&0 0 -> 4 PASS                      (Priority 1)
         * 0 1 1&&&1 1 -> 5 STORE in bitmap           (Priority 1)
         * 0 1 0&&&0 1 -> 3 Tag: ABNORMAL             (Priority 0)
         * else        -> 0 Reinspect                 (Priority 0)
         */
    }
    actions {
        monitor_session;
    }
    default_action : monitor_session(0);
    size : 10;
}
action monitor_session(tag) {
    modify_field(meta.packet_tag, tag);
}

// reinspect
table update_ip2hc_valid_flag_table {
    actions {
        update_ip2hc_valid_flag;
    }
    default_action : update_ip2hc_valid_flag();
    size : ONE_ACTION_TABLE_SIZE;
}
// blackbox stateful_alu s_update_ip2hc_valid_flag{
//     reg : r_ip2hc_valid_flag;
//     condition_lo : meta.packet_tag == 5; /* Update bitmap */

//     update_lo_1_predicate : condition_lo;
//     update_lo_1_value : 1;
//     update_lo_2_predicate : not condition_lo;
//     update_lo_2_value : register_lo;

//     output_value : alu_lo;
//     output_dst : meta.ip2hc_valid_flag;
// }
action update_ip2hc_valid_flag() {
    // s_update_ip2hc_valid_flag.execute_stateful_alu(meta.ip2hc_index);
}

table update_temporary_bitmap_table {
    actions {
        update_temporary_bitmap;
    }
    default_action : update_temporary_bitmap();
    size : ONE_ACTION_TABLE_SIZE;
}
// blackbox stateful_alu s_update_temporary_bitmap{
//     reg : r_temporary_bitmap;
//     condition_lo : meta.packet_tag == 5; /* Update bitmap */

//     update_lo_1_predicate : condition_lo;
//     update_lo_1_value : 1;
//     update_lo_2_predicate : not condition_lo;
//     update_lo_2_value : register_lo;

//     output_predicate : meta.ip2hc_valid_flag == 1;
//     output_value : alu_lo;
//     // output = 1 only when valid == 1 and bitmap == 1
//     output_dst : meta.dirty_hc_hit_flag;
// }
action update_temporary_bitmap() {
    // s_update_temporary_bitmap.execute_stateful_alu_from_hash(temporary_bitmap_index_hash);
}


table set_ip2hc_counter_update_table_2 {
    actions {
        set_ip2hc_counter_update_2;
    }
    default_action : set_ip2hc_counter_update_2();
    size : ONE_ACTION_TABLE_SIZE;
}
action set_ip2hc_counter_update_2() {
    modify_field(meta.ip2hc_counter_update, 2);
}




// If the packet is judged as abnormal because its suspected hop-count,
// handle it according to the nethcf state.
// For learning state, just update r_mismatch_counter
// For filtering state, every abnormal packets should be dropped and
// r_mismatch_counter should be updated as well
table process_mismatch_table {
    actions {
        process_mismatch;
    }
    default_action : process_mismatch();
    size : ONE_ACTION_TABLE_SIZE;
}
// blackbox stateful_alu s_update_mismatch_counter {
//     reg : r_mismatch_counter;
//     update_lo_1_value : register_lo + 1;
// }
action process_mismatch() {
    // s_update_mismatch_counter.execute_stateful_alu(0);
}

table process_mismatch_at_filtering_table {
    actions {
        process_mismatch_at_filtering;
    }
    default_action : process_mismatch_at_filtering();
    size : ONE_ACTION_TABLE_SIZE;
}
action process_mismatch_at_filtering() {
    modify_field(meta.packet_tag, ABNORMAL_FLAG);
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
// blackbox stateful_alu s_update_ip2hc_counter{
//     reg : r_ip2hc_counter;
//     condition_lo : meta.ip2hc_counter_update == 1;
//     condition_hi : meta.ip2hc_valid_flag and meta.dirty_hc_hit_flag == 1;

//     update_lo_1_predicate : condition_lo and condition_hi;
//     update_lo_1_value : register_lo + 1;

//     output_value : alu_lo;
//     output_dst : meta.ip2hc_counter_value;
// }
action update_ip2hc_counter() {
    // s_update_ip2hc_counter.execute_stateful_alu(meta.ip2hc_index);
}

// Set r_report_bitarray
table report_bitarray_set_table {
    actions {
        set_report_bitarray;
    }
    default_action : set_report_bitarray();
    size : ONE_ACTION_TABLE_SIZE;
}
// blackbox stateful_alu s_set_report_bitarray {
//     reg : r_report_bitarray;
//     update_lo_1_value : 1;
// }
action set_report_bitarray() {
    // s_set_report_bitarray.execute_stateful_alu(meta.ip2hc_index);
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
    // CLONE NOT WORKING
    // clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
}
// field_list meta_data_for_clone {
//     ig_intr_md;
//     meta;
// }

// When a packet is missed, direct it to controller at filtering state
table process_miss_at_filtering_table {
    actions {
        process_miss_at_filtering;
    }
    default_action : process_miss_at_filtering();
    size : ONE_ACTION_TABLE_SIZE;
}

action process_miss_at_filtering() {
    // CLONE NOT WORKING
    // clone_ingress_pkt_to_egress(CLONE_SPEC_VALUE, meta_data_for_clone);
    modify_field(meta.packet_tag, ABNORMAL_FLAG);
}

// Forward table, now it just support layer 2
table forward_table {
    reads {
        meta.packet_tag : exact;
        /*
         * #define NORMAL_FLAG 0
         * #define REPLY_SA_FLAG 1
         * #define REPLY_RST_FLAG 2
         * #define ABNORMAL_FLAG 3
         * #define PASS_AND_NOP 4
         * #define SAVE_TO_BITMAP 5
         */
        ig_intr_md.ingress_port : exact;
    }
    actions {
        _drop;
        forward_l2;
        send_back_sa;
        send_back_rst;
    }
    default_action : _drop();
    size : FORWARD_TABLE_SIZE;
}
action forward_l2(egress_port) {
    modify_field(eg_intr_md.egress_port, egress_port);
}
action send_back_sa() {
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
    modify_field(eg_intr_md.egress_port, ig_intr_md.ingress_port);
}
action send_back_rst() {
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
    modify_field(eg_intr_md.egress_port, ig_intr_md.ingress_port);
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
    // MAY NOT BE WORKING
    // truncate(PACKET_TRUNCATE_LENGTH);
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
    // MAY NOT BE WORKING
    // truncate(PACKET_TRUNCATE_LENGTH);
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
                apply(set_ip2hc_counter_update_table_1);
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
                 *  2) ACK + STATE_1 + right SEQ# -> STATE_0 + update BITMAP + VALID_ARRAY
                 *  3) ACK + STATE_1 -> mark as ABNORMAL
                 *  4) OTHERS -> check BITMAP + VALID_ARRAY
                 ****************************************************/
                apply(calculate_session_table_index_table_1);
                apply(calculate_session_table_index_table_2);
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
                    apply(calculate_seqno_diff_table_1);
                    // Add another table to combine SYN+ACK information into a number
                    apply(prepare_tcp_flags_as_real_table_1);
                    // read and update register r_proxy_session_state
                    apply(update_proxy_session_state_table);
                    // Tag packets according to various senarios
                    apply(session_proxy_table);
                }
                if (meta.packet_tag == NORMAL_FLAG){
                    // MONITOR
                    // Add another table to combine SYN+ACK information into a number
                    apply(prepare_tcp_flags_as_real_table_2);
                    // read and update register r_session_seq
                    apply(update_session_seq_table);
                    // calculate SEQ# diff
                    apply(calculate_seqno_diff_table_2);
                    // read and update register r_monitor_session_state
                    apply(update_monitor_session_state_table);
                    // Tag packets according to various senarios
                    apply(session_monitor_table);
                }
                // reinspect
                /* Packet Tags
                 * #define NORMAL_FLAG 0
                 * #define REPLY_SA_FLAG 1
                 * #define REPLY_RST_FLAG 2
                 * #define ABNORMAL_FLAG 3
                 * #define PASS_AND_NOP 4
                 * #define SAVE_TO_BITMAP 5
                 */
                // update r_ip2hc_valid_flag
                apply(update_ip2hc_valid_flag_table);
                // update r_temporary_bitmap
                apply(update_temporary_bitmap_table);
                if (meta.packet_tag == NORMAL_FLAG) {
                    if(meta.dirty_hc_hit_flag == 1){
                        apply(set_ip2hc_counter_update_table_2);
                    }
                    else {
                        // Suspicious packets with mismatched Hop Count value
                        apply(process_mismatch_table);
                        if (meta.nethcf_state == FILTERING_STATE) {
                            apply(process_mismatch_at_filtering_table);
                        }
                    }
                }
            }
            apply(ip2hc_counter_update_table);
            // Hot IP2HC entry process
            if (meta.ip2hc_counter_value > IP2HC_HOT_THRESHOLD) {
                apply(report_bitarray_set_table);
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
    apply(forward_table);
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
