#!/usr/bin/env python
# coding=utf-8

import heapq
import struct
import socket
from config import *


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

    def push_direct(self, item):
        heapq.heappush(self._heap, item)

    def pop(self):
        return heapq.heappop(self._heap)

    def update(self, item_pointer, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        item_pointer[0] = -1 * impact_factor
        heapq.heapify(self._heap)

    def reorgnize():
        heapq.heapify(self._heap)


class CacheHeap:
    def __init__(self, impact_factor_function):
        self._heap = []
        self.impact_factor_function = impact_factor_function

    def push(self, ip_addr, idx, entry_handle, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        # -1 is because we want use heapq to realize large heap
        item = [impact_factor, ip_addr, idx, entry_handle]
        heapq.heappush(self._heap, item)
        return item

    def push_direct(self, item):
        heapq.heappush(self._heap, item)

    def pop(self):
        return heapq.heappop(self._heap)

    def update(self, item_pointer, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        item_pointer[0] = impact_factor
        heapq.heapify(self._heap)

    def reorgnize():
        heapq.heapify(self._heap)


class IP2HC:
    def __init__(self, impact_factor_function, default_hc_list):
        # Init the Impact Heap of the IP2HC
        self.impact_heap = ImpactHeap(impact_factor_function)
        # Init the Cache Heap of the switch
        self.cache_heap = CacheHeap(impact_factor_function)
        # Init each column of the IP2HC table
        self.hc_value = [-1 for ip_addr in range(IP_SPACE_SIZE)]
        self.total_matched = [0 for ip_addr in range(IP_SPACE_SIZE)]
        self.last_matched = [0 for ip_addr in range(IP_SPACE_SIZE)]
        self.heap_pointer = [
            self.impact_heap.push(ip_addr, 0, 0) 
            for ip_addr in range(IP_SPACE_SIZE)
        ]
        self.cache = [
            self.cache_heap.push(idx, idx, idx, 0, 0) 
            for idx in range(CACHE_SIZE)
        ]
        # Load the default_hc_list into IP2HC
        for ip_hc_pair in default_hc_list:
            self.hc_value[ip_hc_pair[0]] = ip_hc_pair[1]
        # Load the default_hc_list into cache
        for idx in range(len(default_hc_list)):
            ip_addr = default_hc_list[idx][0]
            self.cache[idx][1] = ip_addr
            self.heap_pointer[ip_addr][0] = 0

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

    def update(self, ip_addr, hc_value):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        self.hc_value[ip_addr] = hc_value
    
    def sync_match_times(self, idx, times):
        ip_addr = self.cache[idx][1]
        self.last_matched[ip_addr] += times
        self.total_matched[ip_addr] += times
        self.cache_heap.update(
            self.cache[idx], 
            self.total_matched[ip_addr], self.last_matched[ip_addr]
        )

    def get_cached_info(self, cache_idx):
        ip_addr = self.cache[cache_idx][1]
        print len(self.hc_value), ip_addr
        hc_value = self.hc_value[ip_addr]
        return ip_addr, hc_value

    def update_cache(self, miss_counter):
        count = number_to_be_replaced(miss_counter)
        cache_list_to_replace = []
        controller_list_to_replace = []
        update_scheme = {}
        for i in range(count):
            # Select count item to be replaced
            cache_list_to_replace.append(self.cache_heap.pop())
            controller_list_to_replace.append(self.impact_heap.pop())
        for i in range(count):
            cache_item = cache_list_to_replace[i]
            controller_item = controller_list_to_replace[i]
            old_ip_addr = cache_item[1]
            cache_idx = cache_item[2]
            entry_handle = cache_item[3]
            new_ip_addr = controller_item[1]
            # Push new item from controller into cache
            self.cache[cache_idx] = self.cache_heap.push(
                new_ip_addr, cache_idx, entry_handle, 
                total_matched[new_ip_addr], last_matched[new_ip_addr]
            )
            # Set the impact factor of thoes pushed into cache to 0
            controller_item[0] = 0
            self.impact_heap.push_direct(controller)
            update_scheme[cache_idx] = (entry_handle, new_ip_addr, hc_value[new_ip_addr])
            # Set the impact factor of those from cache to normal
            self.impact_heap.update(
                self.heap_pointer[old_ip_addr],
                total_matched[old_ip_addr], last_matched[old_ip_addr]
            )
        return update_scheme

    def update_entry_handle_in_cache(self, cache_idx, entry_handle):
        self.cache[cache_idx][3] = entry_handle

class TCP_Session:
    def __init__(self):
        self.state = [0 for ip_addr in range(IP_SPACE_SIZE)]
        self.seq_number = [0 for ip_addr in range(IP_SPACE_SIZE)]

    def read(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        return self.state[ip_addr], self.seq_number[ip_addr]

    def update(self, ip_addr, state, seq_number):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        self.state[ip_addr] = state
        self.seq_number[ip_addr] = seq_number

