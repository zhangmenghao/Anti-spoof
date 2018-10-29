#!/usr/bin/env python
# coding=utf-8

from scapy.all import *
from data_structure import IP2HC, TCP_Session
from config import *
from switch import NetHCFSwitchBMv2

class NetHCFController:
    def __init__(self, iface, default_hc_list):
        self.switch = NetHCFSwitchBMv2(
            NETHCF_SWITCH_CONFIG, TARGET_SWITCH, TARGET_CODE, TARGET_PORT
        )
        self.iface = iface
        self.ip2hc = IP2HC(impact_factor_function, default_hc_list);
        self.tcp_session = TCP_Session()
        self.miss = 0
        self.mismatch = 0
        self.hcf_state = 0 # 0: learning 1: filtering

    def start(self):
        self.hcf_state = 0
        self.switch_to_learning_state()
        self.load_cache_into_switch()
        sniff(iface=self.iface, prn=packets_callback)

    # Nested function for passing "self" parameter to sniff's callback function
    def packets_callback(self):
        def process_function(pkt):
            if pkt[Ether].type == TYPE_IPV4:
                # This is not a IPv4 packet, ignore it temporarily
                return
            # This is a IPv4 packet
            if pkt[IP].dst == controller:
                # This is update request
                if pkt[IP].proto == TYPE_TCP:
                    # This is a write back request
                    # A SYN ACK ACK packet with replaced dst address
                    self.ip2hc.update(
                        pkt[IP].src, 
                        self.compute_hc(pkt[IP])
                    )
                elif pkt[IP].proto == TYPE_NETHCF:
                    # This is a cache update request
                    self.pull_switch_counters()
                    update_scheme = self.ip2hc.update_cache()
                    self.update_cache_into_switch(update_scheme)
                    self.reset_period_counters()
            else:
                # This is the header of traffic missing IP2HC in the cache
                self.process_packets_miss_cache(pkt)
        return process_function 

    def compute_hc(self, current_ttl):
        hop_count = 0
        hop_count_possible = 0
        # Select initial TTL according to current TTL, and compute HC 
        if 0 <= current_ttl <= 29:
            # Initial TTL may be 30, or 32
            hop_count = 30 - current_ttl
            hop_count_possible = 32 - current_ttl
        elif 30 <= current_ttl <= 31:
            hop_count = 32 - current_ttl
            hop_count_possible = hop_count
        elif 32 <= current_ttl <= 59:
            # Initial TTL may be 60, or 64
            hop_count = 60 - current_ttl
            hop_count_possible = 64 - current_ttl
        elif 60 <= current_ttl <= 63:
            hop_count = 64 - current_ttl
            hop_count_possible = hop_count
        elif 65 <= current_ttl <= 127:
            hop_count = 128 - current_ttl
            hop_count_possible = hop_count
        else:
            hop_count = 255 - current_ttl
            hop_count_possible = hop_count
        return hop_count, hop_count_possible

    def process_packets_miss_cache(self, pkt):
        hc_in_ip2hc = self.ip2hc.read(pkt[IP].src)
        hop_count, hop_count_possible = self.compute_hc(pkt[IP].ttl)
        if hop_count==hc_in_ip2hc or hop_count_possible==hc_in_ip2hc:
            # Update IP2HC match statistics
            self.ip2hc.hit_in_controller(ip_addr, 1)
        else:
            # The HC may not be computed,
            # or the HC should be updated,
            # or this is an abnormal packet
            if pkt[IP].proto != TYPE_TCP:
                # However, we think it is abnormal traffic
                self.mismatch += 1
                return
            if pkt[TCP].flags == "SA":
                self.tcp_session.update(pkt[IP].dst, 1, pkt[TCP].seq)
            elif pkt[TCP].flags == "A":
                state, seq_no = self.tcp_session.read(pkt[IP].dst)
                # This is SYN ACK ACK.
                if state == 1 and pkt[IP].ack == seq_no + 1:
                    # The connection is established
                    self.tcp_session.update(pkt[IP].src, 0, 0)
                    self.ip2hc.update(
                        pkt[IP].src, 
                        self.compute_hc(pkt[IP])
                    )
                    # SYN, SYN ACK ACK, total two times for ip_addr(src)
                    self.hit_in_controller(pkt[IP].src, 2)
                    # Eliminate the effect of SYN
                    self.mismatch -= 1
                else:
                    # Abnormal packet
                    self.mismatch += 1
            else:
                # Such as SYN
                self.mismatch += 1

    # Assume controller is running on the switch
    def pull_switch_counters():
        self.miss = self.switch.read_miss_counter()
        self.mismatch += self.switch.read_mismatch_counter()
        for idx in range(CACHE_SIZE):
            self.ip2hc.sync_match_times(idx, self.switch.read_hits_counter(idx))
    
    def load_cache_into_switch(self):
        for idx in range(CACHE_SIZE):
            ip_addr, hc_value = self.ip2hc.get_cached_info(idx)
            entry_handle = self.switch.add_into_ip2hc_mat(ip_addr, idx)
            if entry_handle != -1:
                self.ip2hc.update_entry_handle_in_cache(idx, entry_handle)
                self.switch.update_hc_value(idx, hc_value)

    def update_cache_into_switch(self, update_scheme):
        for cache_idx in update_scheme.keys():
            entry_handle = update_scheme[cache_idx][0]
            new_ip_addr = update_scheme[cache_idx][1]
            hc_value = update_scheme[cache_idx][2]
            self.switch.delete_from_ip2hc_mat(entry_handle)
            entry_handle = self.switch.add_into_ip2hc_mat(ip_addr, cache_idx)
            if entry_handle != -1:
                self.ip2hc.update_entry_handle_in_cache(cache_idx, entry_handle)
                self.switch.update_hc_value(cache_idx, hc_value)
    
    def reset_period_counters(self):
        self.miss = 0
        self.mismatch = 0
        self.switch.reset_miss_counter()
        self.switch.reset_mismatch_counter()
        self.switch.reset_hits_counter()
        self.ip2hc.reset_last_matched()

if __name__ == "__main__":
    controller = NetHCFController("enp0s8", [])
