#!/usr/bin/env python
# coding=utf-8

from scapy.all import *
from data_structure import IP2HC, TCP_Session

CONTROLLER_IP = "192.168.56.101"
TYPE_IPV4 = 0x0800
ALPHA = 0.2

def impact_factor_function(total_matched, last_matched):
    impact_factor = ALPHA * total_matched + (1 - ALPHA) * last_matched
    return impact_factor

class NetHCFController:
    def __init__(self, iface, impact_factor_function, default_hc_list, method):
        self.iface = iface
        self.ip2hc = IP2HC(impact_factor_function, default_hc_list);
        self.tcp_session = TCP_Session()
        self.method = method

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


    def process_packets(self):
        sniff(iface=self.iface, prn=packets_callback)

    # nested function for passing "self" parameter to sniff's callback function
    def packets_callback(self):
        def method_1_process_function(pkt):
            if pkt[Ether].type == TYPE_IPV4:
                # this is a IPv4 packet
                if pkt[IP].dst == controller:
                    # this is update request
                    pkt
                else:
                    # this is the header of traffic missing IP2HC in the cache
                    hc_in_ip2hc = self.ip2hc.read(pkt[IP].src)
                    current_ttl = pkt[IP].ttl
                    hop_count, hop_count_possible = self.compute_hc(current_ttl)
                    if hop_count == hc_in_ip2hc or \
                       hop_count_possible == hc_in_ip2hc:
                        # Update IP2HC match statistics
                        self.ip2hc.hit_in_controller(ip_addr, 1)
                    else:
                        # The HC may not be computed,
                        # or the HC should be updated,
                        # or this is an abnormal packet
                        if pkt[TCP].flags == "SA":
                            self.tcp_session.write(pkt[IP].dst, 1, pkt[TCP].seq)
            else:
                # this is not a IPv4 packet
                pkt
        def method_2_process_function(pkt):
            pkt
        if method == 1:
            return method_1_process_function
        else:
            return method_2_process_function
        return process_packets

if __name__ == "__main__":
    controller = NetHCFController("enp0s8")
