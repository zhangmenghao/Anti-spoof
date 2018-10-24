#!/usr/bin/env python
# coding=utf-8

from scapy.all import *

CONTROLLER_IP = "192.168.56.101"
TYPE_IPV4 = 0x0800

class NetHCFController:
    def __init__(self, iface):
        self.iface = iface
        self.IP2HC = IP2HC();

    def process_packets(self):
        sniff(iface=self.iface, prn=packets_callback)

    # nested function for passing "self" parameter to sniff's callback function
    def packets_callback(self):
        def process_function(pkt):
            if pkt[Ether].type == TYPE_IPV4:
                # this is a IPv4 packet
                if pkt[IP].src == controller:
                    # this is update request
                else:
                    # this is the header of traffic missing IP2HC in the cache
            else:
                # this is not a IPv4 packet
                current_ttl = pkt[IP].ttl
                hop_count = 0
                hop_count_possible = 0
                hc_in_ip2hc = self.IP2HC.read(pkt[IP].src)
                if 0 <= current_ttl <= 29:
                    hop_count = 30 - current_ttl
                    hop_count_possible = 32 - current_ttl
                elif 30 <= current_ttl <= 31:
                    hop_count = 32 - current_ttl
                    hop_count_possible = hop_count
                elif 32 <= current_ttl <= 59:
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
                if hop_count == hc_in_ip2hc or hop_count_possible = hc_in_ip2hc:
                    # Update IP2HC
                else:
                    # The HC may not be computed,
                    # or the HC should be updated,
                    # or this is an abnormal packet
        return process_packets

if __name__ == "__main__":
    controller = NetHCFController("enp0s8")
