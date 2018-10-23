#!/usr/bin/env python
# coding=utf-8

from scapy.all import *

CONTROLLER_IP = "192.168.56.101"
TYPE_IPV4 = 0x0800

class NetHCFController:
    def __init__(self, iface):
        self.iface = iface

    def process_packets(self):
        sniff(iface=self.iface, prn=packets_callback)

    # nested function for passing "self" parameter to sniff's callback function
    def packets_callback(self):
        def process_function(pkt):
            if pkt[Ether].type != TYPE_IPV4:
                # this is a IPv4 packet
            else:
                # this is not a IPv4 packet
        return process_packets

if __name__ == "__main__":
    controller = NetHCFController("enp0s8")
