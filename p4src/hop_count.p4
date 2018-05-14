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
#define TCP_SESSION_MAP_BITS 8
#define TCP_SESSION_MAP_SIZE 256 // 2^8
#define TCP_SESSION_STATE_SIZE 8
#define IP_TO_HC_INDEX_BITS 24
#define IP_TO_HC_TABLE_SIZE 16777216 // 2^24

header_type ingress_metadata_t {
    fields {
        hop_count: HOP_COUNT_SIZE;
        tcp_session_map_index: TCP_SESSION_MAP_BITS;
        tcp_session_state: TCP_SESSION_STATE_SIZE; // 1: received SYN-ACK
        tcp_session_seq: 32; // 1: received SYN-ACK
        ip_to_hc_index : IP_TO_HC_INDEX_BITS;
        hcf_state: 1; // 0: Learning 1: Filtering
    }
}

metadata ingress_metadata_t ingress_metadata;

action compute_hc(initial_ttl) {
    subtract(ingress_metadata.hop_count, initial_ttl, ipv4.ttl);
}

action _drop() {
    drop();
}

table hc_compute_table {
    reads {
        ipv4.ttl: range;
    }
    actions {
        _drop;
        compute_hc;
    }
    size: HC_COMPUTE_TABLE_SIZE;
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
        ingress_metadata.tcp_session_map_index, 0,
        tcp_session_map_hash, TCP_SESSION_MAP_SIZE
    );
    register_read(
        ingress_metadata.tcp_session_state, session_state, 
        ingress_metadata.tcp_session_map_index
    );
    register_read(
        ingress_metadata.tcp_session_seq, session_seq,
        ingress_metadata.tcp_session_map_index
    );
    shift_right(
        ingress_metadata.ip_to_hc_index, 
        ipv4.dstAddr, 32 - IP_TO_HC_INDEX_BITS
    );
}

action lookup_reverse_session_map() {
    modify_field_with_hash_based_offset(
        ingress_metadata.tcp_session_map_index, 0,
        reverse_tcp_session_map_hash, TCP_SESSION_MAP_SIZE
    );
    register_read(
        ingress_metadata.tcp_session_state, session_state, 
        ingress_metadata.tcp_session_map_index
    );
    register_read(
        ingress_metadata.tcp_session_seq, session_seq,
        ingress_metadata.tcp_session_map_index
    );
    shift_right(
        ingress_metadata.ip_to_hc_index, 
        ipv4.dstAddr, 32 - IP_TO_HC_INDEX_BITS
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
    register_write(session_state, ingress_metadata.tcp_session_map_index, 1);
    register_write(
        session_seq, ingress_metadata.tcp_session_map_index, tcp.seqNo
    );
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
    register_write(session_state, ingress_metadata.tcp_session_map_index, 0);
    register_write(
        ip_to_hc, 
        ingress_metadata.ip_to_hc_index, 
        ingress_metadata.hop_count
    );
}

table session_complete_table {
    reads {
        tcp.ack : exact;
    }
    actions {
        _drop;
        complete_session;
    }
}

control ingress {
    apply(session_check_table);
    if (ingress_metadata.tcp_session_state == 1) {
        if (tcp.ackNo == ingress_metadata.tcp_session_seq + 1) {
            apply(hc_compute_table);
            apply(session_complete_table);
        }
    }
    else if (ingress_metadata.tcp_session_state == 0) {
        if (tcp.syn == 1 and tcp.ack == 1) {
            apply(session_init_table);
        }
    }
}
