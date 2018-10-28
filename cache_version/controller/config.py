#!/usr/bin/env python
# coding=utf-8

import socket
import struct

CONTROLLER_IP = "192.168.56.101"
TYPE_IPV4 = 0x0800
TYPE_TCP = 0x06
# # TYPE_NETHCF_IP2HC is used for transfering counter arrays of switch
# TYPE_NETHCF_IP2HC = 0xAB
# # TYPE_NETHCF_MISX is used for transfering miss and mismatch counters
# TYPE_NETHCF_MISX = 0xCD
TYPE_NETHCF = 0xAB
ALPHA = 0.2
LAMBDA = 1
THETA = 20
CACHE_SIZE = 100000

BMV2_PATH = "/home/dracula/p4_environment/behavioral-model"
TARGET_SWITCH = BMV2_PATH +  "/targets/simple_switch/sswitch_CLI"
TARGET_CODE = "hop_count.json"
TARGET_PORT = 22223
# counter name in p4
MISS_COUNTER = "miss_counter"
MISMATCH_COUNTER = "mismatch_counter"
IP2HC_COUNTER = "hc_counter"
# hc value register array name in p4
IP2HC_REGISTER = "hc_value"
# IP2HC Match-Action-Table name in p4
IP2HC_MAT = "IP2HC"
# IP2HC Match-Action-Table action name in p4
READ_HC = "read_hc"

ERROR_HINT_STR = (
    "Please check whether the switch "
    "is well configured and running."
)

def READ_MISS_COUNTER_CMD():
    return (
        '''echo "counter_read %s 0" | %s %s %d''' 
        % (MISS_COUNTER, TARGET_SWITCH, TARGET_CODE, TARGET_PORT)
    )

def READ_MISMATCH_COUNTER_CMD():
    return (
        '''echo "counter_read %s 0" | %s %s %d''' 
        % (MISMATCH_COUNTER, TARGET_SWITCH, TARGET_CODE, TARGET_PORT)
    )

def READ_HITS_COUNTER_CMD(cache_idx):
    return (
        '''echo "counter_read %s %d" | %s %s %d''' 
        % (IP2HC_COUNTER, cache_idx, TARGET_SWITCH, TARGET_CODE, TARGET_PORT)
    )

# Add entry into IP2HC Match-Action-Table
def ADD_INTO_IP2HC_MAT_CMD(ip_addr, cache_idx):
    if type(ip_addr) != str:
        ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
    return (
        '''echo "table_add %s %s %s => %d 0" | %s %s %d''' 
        % (IP2HC_MAT, READ_HC, ip_addr, cache_idx, 
           TARGET_SWITCH, TARGET_CODE, TARGET_PORT)
    )

# Get the entry index in IP2HC-MAT
def INDEX_IP2HC_MAT_CMD(ip_addr, cache_idx):
    if type(ip_addr) != str:
        ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
    return (
        '''echo "table_dump_entry_from_key %s %s 0" | %s %s %d''' 
        % (IP2HC_MAT, ip_addr, TARGET_SWITCH, TARGET_CODE, TARGET_PORT)
    )

# Add entry into IP2HC Match-Action-Table
def DELETE_FROM_IP2HC_MAT_CMD(entry_handle):
    return (
        '''echo "table_delete %s %d" | %s %s %d''' 
        % (IP2HC_MAT, entry_handle, TARGET_SWITCH, TARGET_CODE, TARGET_PORT)
    )

def UPDATE_HC_VALUE_CMD(cache_idx, hc_value):
    return (
        '''echo "register_write %s %d %d" | %s %s %d''' 
        % (IP2HC_REGISTER, cache_idx, hc_value, 
           TARGET_SWITCH, TARGET_CODE, TARGET_PORT)
    )

def impact_factor_function(total_matched, last_matched):
    impact_factor = ALPHA * total_matched + (1 - ALPHA) * last_matched
    return impact_factor

def number_to_be_replaced(miss_counter):
    return max(miss_counter * LAMBDA, THETA)
