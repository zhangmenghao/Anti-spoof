#!/usr/bin/env python
# coding=utf-8

import os
import time

BMV2_PATH = "/home/dracula/Downloads/p4_environment/behavioral-model"
target_switch = BMV2_PATH +  "/targets/simple_switch/sswitch_CLI"
target_code = "hop_count.json"
target_port = 22223

# Two threshold for state switching in HCF
learn_to_filter_thr = 20
filter_to_learn_thr = 15
sample_period_time = 1

error_hint_str = (
    "Please check whether the switch "
    "is well configured and running."
)

read_abnormal_counter_cmd = (
    '''echo "counter_read abnormal_counter 0" | %s %s %d''' 
    % (target_switch, target_code, target_port)
)

reset_abnormal_counter_cmd = (
    '''echo "counter_reset abnormal_counter" | %s %s %d''' 
    % (target_switch, target_code, target_port)
)

read_current_state_cmd = (
    '''echo "register_read current_state 0" | %s %s %d''' 
    % (target_switch, target_code, target_port)
)

switch_to_learning_cmd = (
    '''echo "register_write current_state 0 0" | %s %s %d''' 
    % (target_switch, target_code, target_port)
)

switch_to_filtering_cmd = (
    '''echo "register_write current_state 0 1" | %s %s %d''' 
    % (target_switch, target_code, target_port)
)

def read_abnormal_counter():
    result = os.popen(read_abnormal_counter_cmd).read()
    # Extract abnormal_counter from result
    try:
        packets_num_str = result[result.index("packets="):].split(',')[0]
        abnormal_counter = int(packets_num_str.split('=')[1])
    except:
        print "Error: Can't read abnormal_counter!\n"
        print error_hint_str
        return -1
    else:
        return abnormal_counter

def reset_abnormal_counter():
    result = os.popen(reset_abnormal_counter_cmd).read()
    if "Done" in result:
        return 0
    else:
        print "Error: Can't reset abnormal_counter!\n"
        print error_hint_str
        return -1

def read_current_state():
    result = os.popen(read_current_state_cmd).read()
    # Extract current_state from result
    try:
        current_state_str = result[result.index("current_state[0]="):].split()[1]
        current_state = int(current_state_str)
    except:
        print "Error: Can't read register current_state!\n"
        print error_hint_str
        return -1
    else:
        return current_state

def switch_to_learning():
    result = os.popen(switch_to_learning_cmd).read()
    if "Done" in result:
        return 0
    else:
        print "Error: Can't write register current_state!\n"
        print error_hint_str
        return -1

def switch_to_filtering():
    result = os.popen(switch_to_filtering_cmd).read()
    if "Done" in result:
        return 0
    else:
        print "Error: Can't write register current_state!\n"
        print error_hint_str
        return -1

def output_debug_info(current_state, abnormal_counter):
        if current_state == 0:
            print "Debug: switch is in learning state!"
        elif current_state == 1:
            print "Debug: switch is in filtering state!"
        print "Debug: abnormal_counter in last period is %d" % abnormal_counter

if __name__ == "__main__":
    reset_abnormal_counter()
    while True:
        abnormal_counter = read_abnormal_counter()
        current_state = read_current_state()
        output_debug_info(current_state, abnormal_counter)
        # Switch state in terms of abnormal_counter in last period
        if current_state == 0 and abnormal_counter > learn_to_filter_thr:
            switch_to_filtering()
        elif current_state == 1 and abnormal_counter < filter_to_learn_thr:
            switch_to_learning()
        # Reset counter for next period
        reset_abnormal_counter()
        time.sleep(sample_period_time)
