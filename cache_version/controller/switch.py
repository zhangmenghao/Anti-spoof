#!/usr/bin/env python
# coding=utf-8

class NetHCFSwitchBMv2:
    def __init__(self, switch_config, target_switch, target_code, target_port):
        self.miss_counter = switch_config["miss_counter"],
        self.mismatch_counter = switch_config["mismatch_counter"]
        self.ip2hc_counter = switch_config["ip2hc_counter"]
        self.ip2hc_register = switch_config["ip2hc_register"]
        self.ip2hc_mat = switch_config["ip2hc_mat"]
        self.read_hc_function = switch_config["read_hc_function"]
        self.target_switch = target_switch
        self.target_code = target_code
        self.target_port = target_port
        self.error_hint_str = (
            "Please check whether the switch "
            "is well configured and running."
        )

    def read_miss_counter_cmd():
        return (
            '''echo "counter_read %s 0" | %s %s %d''' 
            % (self.miss_counter, 
               self.target_switch, self.target_code, self.target_port)
        )

    def read_miss_counter():
        result = os.popen(self.read_miss_counter_cmd()).read()
        try:
            packets_num_str = result[result.index("packets="):].split(',')[0]
            miss_counter_value = int(packets_num_str.split('=')[1])
        except:
            print "Error: Can't read miss counter!\n"
            print self.error_hint_str
            return 0
        else:
            return miss_counter_value

    def read_mismatch_counter_cmd():
        return (
            '''echo "counter_read %s 0" | %s %s %d''' 
            % (self.mismatch_counter, 
               self.target_switch, self.target_code, self.target_port)
        )

    def read_mismatch_counter():
        result = os.popen(self.read_mismatch_counter_cmd()).read()
        try:
            packets_num_str = result[result.index("packets="):].split(',')[0]
            mismatch_counter_value = int(packets_num_str.split('=')[1])
        except:
            print "Error: Can't read mismatch counter!\n"
            print self.error_hint_str
            return 0
        else:
            return mismatch_counter_value

    def read_hits_counter_cmd(cache_idx):
        return (
            '''echo "counter_read %s %d" | %s %s %d''' 
            % (self.ip2hc_counter, cache_idx, 
               self.target_switch, self.target_code, self.target_port)
        )

    def read_hits_counter(cache_idx):
        result = os.popen(self.read_hits_counter_cmd(cache_idx)).read()
        try:
            packets_str = result[result.index("packets="):].split(',')[0]
            match_times = int(packets_str.split('=')[1]) 
        except:
            print "Error: Can't read hits counter!\n"
            print self.error_hint_str
            return 0
        else:
            return match_times

    # Add entry into IP2HC Match-Action-Table
    def add_into_ip2hc_mat_cmd(ip_addr, cache_idx):
        if type(ip_addr) != str:
            ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
        return (
            '''echo "table_add %s %s %s => %d 0" | %s %s %d''' 
            % (self.ip2hc_mat, self.read_hc_function, ip_addr, cache_idx, 
               self.target_switch, self.target_code, self.target_port)
        )

    def add_into_ip2hc_mat(ip_addr, cache_idx):
        result = os.popen(self.add_into_ip2hc_mat_cmd(ip_addr,cache_idx)).read()
        try:
            entry_handle_str = result[result.index("handle"):].split()[1]
            entry_handle = int(entry_handle_str)
        except:
            print "Error: Can't add entry into IP2HC Match Action Table!\n"
            print self.error_hint_str
            return -1
        else:
            return entry_handle

    def update_hc_value_cmd(cache_idx, hc_value):
        return (
            '''echo "register_write %s %d %d" | %s %s %d''' 
            % (self.ip2hc_register, cache_idx, hc_value, 
               self.target_switch, self.target_code, self.target_port)
        )

    def update_hc_value(cache_idx, hc_value):
        result = os.popen(self.update_hc_value_cmd(cache_idx, hc_value)).read()
        if "Done" not in result:
            print "Error: Can't write into hc value register!\n"
            print self.error_hint_str

    # Add entry into IP2HC Match-Action-Table
    def delete_from_ip2hc_mat_cmd(entry_handle):
        return (
            '''echo "table_delete %s %d" | %s %s %d''' 
            % (self.ip2hc_mat, entry_handle, 
               self.target_switch, self.target_code, self.target_port)
        )

    def delete_from_ip2hc_mat(entry_handle):
        result = os.popen(self.delete_from_ip2hc_mat_cmd(entry_handle)).read()
        if "Invalid" in result:
            print "Error: Can't delete entry from IP2HC MatchActionTable!\n"
            print self.error_hint_str

    # Get the entry index in IP2HC-MAT
    def index_ip2hc_mat_cmd(ip_addr, cache_idx):
        if type(ip_addr) != str:
            ip_addr = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_addr)))
        return (
            '''echo "table_dump_entry_from_key %s %s 0" | %s %s %d''' 
            % (self.ip2hc_mat, ip_addr, 
               self.target_switch, self.target_code, self.target_port)
        )
