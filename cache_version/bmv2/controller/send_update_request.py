#!/usr/bin/env python
# coding=utf-8

from scapy.all import *

sendp(Ether()/IP(dst="192.168.56.101",ttl=64, proto=0xAB), iface="s1-eth3")
