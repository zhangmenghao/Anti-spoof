#!/usr/bin/env python
# coding=utf-8

import heapq
import struct
import socket

class ImpactHeap:
    def __init__(self, impact_factor_function):
        self._heap = []
        self.impact_factor_function = impact_factor_function

    def push(self, ip_addr, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        # -1 is because we want use heapq to realize large heap
        impact_factor *= -1
        item = (impact_factor, ip_addr)
        heapq.heappush(self._heap, item)
        return item

    def pop(self):
        return heapq.heappop(self._heap)

    def update(self, item_pointer, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        item_pointer[0] = -1 * impact_factor
        heapq.heapify(self._heap)

class IP2HC:
    def __init__(self, impact_factor_function, default_hc_list):
        # Init the Impact Heap of the IP2HC
        self.impact_heap = ImpactHeap(impact_factor_function)
        # Init each column of the IP2HC table
        self.hc_value = [-1 for ip_addr in range(2^32)]
        self.total_matched = [0 for ip_addr in range(2^32)]
        self.last_matched = [0 for ip_addr in range(2^32)]
        self.cached = [0 for ip_addr in range(2^32)]
        self.heap_pointer = [
            self.impact_heap.push(ip_addr, 0, 0) for ip_addr in range(2^32)
        ]
        # Load the default_hc_list into IP2HC
        for ip_hc_pair in default_hc_list:
            self.hc_value[ip_hc_pair[0]] = ip_hc_pair[1]

    def read(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        return self.hc_value[ip_addr]

    def hit_in_controller(self, ip_addr, times):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        self.last_matched[ip_addr] += times
        self.total_matched[ip_addr] += times
        self.impact_heap.update(
            self.heap_pointer[ip_addr], 
            self.total_matched[ip_addr], self.last_matched[ip_addr]
        )

class TCP_Session:
    def __init__(self):
        self.state = [0 for ip_addr in range(2^32)]
        self.seq_number = [0 for ip_addr in range(2^32)]

    def read(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        return self.state[ip_addr], self.seq_number[ip_addr]

    def write(self, ip_addr, state, seq_number):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        self.state[ip_addr] = state
        self.seq_number[ip_addr] = seq_number

