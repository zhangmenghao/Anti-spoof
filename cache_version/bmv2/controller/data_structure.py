#!/usr/bin/env python
# coding=utf-8

import sys
import heapq
import struct
import socket
from array import array
from config import *

class ImpactHeap:
    # item: [impact_factor, ip_addr]
    def __init__(self, impact_factor_function, mpmgr):
        self._heap = mpmgr.list()
        self.impact_factor_function = impact_factor_function

    def push(self, ip_addr, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        # -1 is because we want use heapq to realize large heap
        impact_factor *= -1
        item = [impact_factor, ip_addr]
        heapq.heappush(self._heap, item)
        return item

    def push_direct(self, item):
        heapq.heappush(self._heap, item)

    def pop(self):
        return heapq.heappop(self._heap)

    def update(self, ip_addr, total_matched, last_matched):
        impact_factor = self.impact_factor_function(total_matched, last_matched)
        heap_idx = self.get_heap_index(ip_addr)
        heap_entry = self._heap[heap_idx]
        heap_entry[IMPACT_HEAP_IMPACT_FACTOR_FLAG] = -1 * impact_factor
        self._heap[heap_idx] = heap_entry
        heapq.heapify(self._heap)

    def reorgnize(self):
        heapq.heapify(self._heap)

    def get_heap_index(self, ip_addr):
        for index, item in enumerate(self._heap):
            if item[IMPACT_HEAP_IP_ADDR_FLAG] == ip_addr:
                return index
        if DEBUG_OPTION:
            print(
                "Error: Can't find entry in impact heap for ip %d..." % ip_addr
            )
            return -1

class IP2HC:
    def __init__(self, impact_factor_function, default_hc_list, mpmgr):
        # Count of the ip-hc pairs in IP2HC table
        self.count = mpmgr.Value('I', 0)
        # Length of bits to devide ip address pertime
        self.devide_bits = DEVIDE_BITS
        if 32 % self.devide_bits != 0:
            print(
                "Warning: Please check DEVIDE_BITS in "
                "config.py and select from [2, 4, 8, 16]"
            )
        # A tree-like structure for IP2HC table
        # IP2HC table item: [prefix_len, Hop-Count, total_matched, last_matched]
        self._ip2hc = mpmgr.dict()
        # key list of every IP2HC item
        self.key_list_set = mpmgr.list()
        # Init the Impact Heap of the IP2HC
        self.impact_heap = ImpactHeap(impact_factor_function, mpmgr)
        # cache item: [ip_addr, entry_handle]
        self.cache = mpmgr.list()
        print("Cache List Size: %d" % sys.getsizeof(self.cache))
        # Load the default_hc_list into IP2HC and cache
        if len(default_hc_list) > CACHE_SIZE:
            print("Warning: the cache cannot hold the whole default_hc_list")
        for ip_addr in default_hc_list.keys():
            hc_value = default_hc_list[ip_addr]
            cache_idx = len(self.cache)
            # Load into IP2HC
            self.add_into_ip2hc(ip_addr, 32, hc_value)
            # Load into cache
            self.cache.append([ip_addr, cache_idx])

    def add_into_ip2hc(self, ip_addr, prefix_len, hc_value):
        mask = (1 << self.devide_bits) - 1
        local_ip2hc = self._ip2hc
        key_list = []
        devide_steps = int(32 / self.devide_bits)
        for i in range(devide_steps):
            ip_addr_part = (ip_addr >> (32 - 8 * (i + 1))) & mask
            if i == devide_steps - 1:
                # Last level
                if i * self.devide_bits == prefix_len:
                    self.key_list_set.append(key_list)
                    key_list.append(IP2HC_HIT_KEY)
                    set_mpmgr_dict(
                        self._ip2hc, key_list, [prefix_len, hc_value, 0, 0]
                    )
                    self.impact_heap.push(ip_addr, 0, 0)
                    self.count.value += 1
                    return
                for j in range(self.devide_bits):
                    ip_addr_bit = (ip_addr_part >> (self.devide_bits-j-1)) & 1
                    key_list.append(ip_addr_bit)
                    if ip_addr_bit in local_ip2hc:
                        local_ip2hc = local_ip2hc[ip_addr_bit]
                    else:
                        tmp_dict = {}
                        set_mpmgr_dict(self._ip2hc, key_list, tmp_dict)
                        local_ip2hc = tmp_dict
                    if i * self.devide_bits + j + 1 == prefix_len:
                        # Last bit
                        self.key_list_set.append(key_list)
                        key_list.append(IP2HC_HIT_KEY)
                        set_mpmgr_dict(
                            self._ip2hc, key_list, [prefix_len, hc_value, 0, 0]
                        )
                        self.impact_heap.push(ip_addr, 0, 0)
                        self.count.value += 1
                        return
            else:
                key_list.append(ip_addr_part)
                if ip_addr_part in local_ip2hc:
                    local_ip2hc = local_ip2hc[ip_addr_part]
                else:
                    tmp_dict = {}
                    set_mpmgr_dict(self._ip2hc, key_list, tmp_dict)
                    local_ip2hc = tmp_dict
        return

    def read_hc(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        mask = (1 << self.devide_bits) - 1
        local_ip2hc = self._ip2hc
        devide_steps = int(32 / self.devide_bits)
        for i in range(devide_steps):
            ip_addr_part = (ip_addr >> (32 - self.devide_bits * (i+1))) & mask
            if i == devide_steps - 1:
                # Last level
                if IP2HC_HIT_KEY in local_ip2hc:
                    # Prefix Length is i * self.devide_bits
                    return local_ip2hc[IP2HC_HIT_KEY][IP2HC_HOP_COUNT_FLAG]
                for j in range(self.devide_bits):
                    ip_addr_bit = (ip_addr_part >> (self.devide_bits-j-1)) & 1
                    if ip_addr_bit in local_ip2hc:
                        local_ip2hc = local_ip2hc[ip_addr_bit]
                    else:
                        return DEFAULT_HC
                    if IP2HC_HIT_KEY in local_ip2hc:
                        return local_ip2hc[IP2HC_HIT_KEY][IP2HC_HOP_COUNT_FLAG]
            else:
                if ip_addr_part in local_ip2hc:
                    local_ip2hc = local_ip2hc[ip_addr_part]
                else:
                    return DEFAULT_HC
        return DEFAULT_HC

    def update_hc(self, ip_addr, hc_value):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        mask = (1 << self.devide_bits) - 1
        local_ip2hc = self._ip2hc
        key_list = []
        devide_steps = int(32 / self.devide_bits)
        for i in range(devide_steps):
            ip_addr_part = (ip_addr >> (32 - self.devide_bits * (i+1))) & mask
            if i == devide_steps - 1:
                # Last level
                if IP2HC_HIT_KEY in local_ip2hc:
                    # Prefix Length is i * self.devide_bits
                    key_list.append(IP2HC_HIT_KEY)
                    key_list.append(1)
                    set_mpmgr_dict(self._ip2hc, key_list, hc_value)
                for j in range(self.devide_bits):
                    ip_addr_bit = (ip_addr_part >> (self.devide_bits-j-1)) & 1
                    key_list.append(ip_addr_bit)
                    if ip_addr_bit in local_ip2hc:
                        local_ip2hc = local_ip2hc[ip_addr_bit]
                    else:
                        self.add_into_ip2hc(ip_addr, 32, hc_value)
                    if IP2HC_HIT_KEY in local_ip2hc:
                        key_list.append(IP2HC_HIT_KEY)
                        key_list.append(1)
                        set_mpmgr_dict(self._ip2hc, key_list, hc_value)
            else:
                key_list.append(ip_addr_part)
                if ip_addr_part in local_ip2hc:
                    local_ip2hc = local_ip2hc[ip_addr_part]
                else:
                    self.add_into_ip2hc(ip_addr, 32, hc_value)

    def read_match_times(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        mask = (1 << self.devide_bits) - 1
        local_ip2hc = self._ip2hc
        devide_steps = int(32 / self.devide_bits)
        for i in range(devide_steps):
            ip_addr_part = (ip_addr >> (32 - self.devide_bits * (i+1))) & mask
            if i == devide_steps - 1:
                # Last level
                if IP2HC_HIT_KEY in local_ip2hc:
                    # Prefix Length is i * self.devide_bits
                    ip2hc_item = local_ip2hc[IP2HC_HIT_KEY]
                    return ip2hc_item[IP2HC_TOTAL_MATCHED_FALG], \
                           ip2hc_item[IP2HC_LAST_MATCHED_FALG]
                for j in range(self.devide_bits):
                    ip_addr_bit = (ip_addr_part >> (self.devide_bits-j-1)) & 1
                    if ip_addr_bit in local_ip2hc:
                        local_ip2hc = local_ip2hc[ip_addr_bit]
                    else:
                        return 0, 0
                    if IP2HC_HIT_KEY in local_ip2hc:
                        ip2hc_item = local_ip2hc[IP2HC_HIT_KEY]
                        return ip2hc_item[IP2HC_TOTAL_MATCHED_FALG], \
                               ip2hc_item[IP2HC_LAST_MATCHED_FALG]
            else:
                if ip_addr_part in local_ip2hc:
                    local_ip2hc = local_ip2hc[ip_addr_part]
                else:
                    return 0, 0
        return 0, 0

    def update_match_times(self, ip_addr, times):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        mask = (1 << self.devide_bits) - 1
        local_ip2hc = self._ip2hc
        key_list = []
        devide_steps = int(32 / self.devide_bits)
        for i in range(devide_steps):
            ip_addr_part = (ip_addr >> (32 - self.devide_bits * (i+1))) & mask
            if i == devide_steps - 1:
                # Last level
                if IP2HC_HIT_KEY in local_ip2hc:
                    # Prefix Length is i * self.devide_bits
                    key_list.append(IP2HC_HIT_KEY)
                    current_total_matched = \
                            local_ip2hc[IP2HC_HIT_KEY][IP2HC_TOTAL_MATCHED_FALG]
                    current_last_matched = \
                            local_ip2hc[IP2HC_HIT_KEY][IP2HC_LAST_MATCHED_FALG]
                    current_total_matched += times
                    current_last_matched += times
                    key_list.append(IP2HC_TOTAL_MATCHED_FALG)
                    set_mpmgr_dict(self._ip2hc, key_list, current_total_matched)
                    key_list.pop()
                    key_list.append(IP2HC_LAST_MATCHED_FALG)
                    set_mpmgr_dict(self._ip2hc, key_list, current_last_matched)
                    key_list.pop()
                    self.impact_heap.update(
                        ip_addr, current_total_matched, current_last_matched
                    )
                    return 0
                for j in range(self.devide_bits):
                    ip_addr_bit = (ip_addr_part >> (self.devide_bits-j-1)) & 1
                    key_list.append(ip_addr_bit)
                    if ip_addr_bit in local_ip2hc:
                        local_ip2hc = local_ip2hc[ip_addr_bit]
                    else:
                        print(
                            "Error: can't find info for this ip %d in IP2HC"\
                            % ip_addr
                        )
                        return -1
                    if IP2HC_HIT_KEY in local_ip2hc:
                        key_list.append(IP2HC_HIT_KEY)
                        current_total_matched = \
                            local_ip2hc[IP2HC_HIT_KEY][IP2HC_TOTAL_MATCHED_FALG]
                        current_last_matched = \
                            local_ip2hc[IP2HC_HIT_KEY][IP2HC_LAST_MATCHED_FALG]
                        current_total_matched += times
                        current_last_matched += times
                        key_list.append(IP2HC_TOTAL_MATCHED_FALG)
                        set_mpmgr_dict(
                            self._ip2hc, key_list, current_total_matched
                        )
                        key_list.pop()
                        key_list.append(IP2HC_LAST_MATCHED_FALG)
                        set_mpmgr_dict(
                            self._ip2hc, key_list, current_last_matched
                        )
                        key_list.pop()
                        self.impact_heap.update(
                            ip_addr, current_total_matched, current_last_matched
                        )
                        return 0
            else:
                key_list.append(ip_addr_part)
                if ip_addr_part in local_ip2hc:
                    local_ip2hc = local_ip2hc[ip_addr_part]
                else:
                    print(
                        "Error: can't find info for this ip %d in IP2HC"%ip_addr
                    )
                    return -1
        print("Error: can't find info for this ip %d in IP2HC" % ip_addr)
        return -1

    def sync_match_times(self, cache_idx, times):
        ip_addr = self.cache[cache_idx][CACHE_IP_ADDR_FLAG]
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        mask = (1 << self.devide_bits) - 1
        local_ip2hc = self._ip2hc
        key_list = []
        devide_steps = int(32 / self.devide_bits)
        for i in range(devide_steps):
            ip_addr_part = (ip_addr >> (32 - self.devide_bits * (i+1))) & mask
            if i == devide_steps - 1:
                # Last level
                if IP2HC_HIT_KEY in local_ip2hc:
                    # Prefix Length is i * self.devide_bits
                    key_list.append(IP2HC_HIT_KEY)
                    current_total_matched = \
                            local_ip2hc[IP2HC_HIT_KEY][IP2HC_TOTAL_MATCHED_FALG]
                    current_last_matched = \
                            local_ip2hc[IP2HC_HIT_KEY][IP2HC_LAST_MATCHED_FALG]
                    current_total_matched += times
                    current_last_matched += times
                    key_list.append(IP2HC_TOTAL_MATCHED_FALG)
                    set_mpmgr_dict(self._ip2hc, key_list, current_total_matched)
                    key_list.pop()
                    key_list.append(IP2HC_LAST_MATCHED_FALG)
                    set_mpmgr_dict(self._ip2hc, key_list, current_last_matched)
                    key_list.pop()
                    return 0
                for j in range(self.devide_bits):
                    ip_addr_bit = (ip_addr_part >> (self.devide_bits-j-1)) & 1
                    key_list.append(ip_addr_bit)
                    if ip_addr_bit in local_ip2hc:
                        local_ip2hc = local_ip2hc[ip_addr_bit]
                    else:
                        print(
                            "Error: can't find info for this ip %d in IP2HC"\
                            % ip_addr
                        )
                        return -1
                    if IP2HC_HIT_KEY in local_ip2hc:
                        key_list.append(IP2HC_HIT_KEY)
                        current_total_matched = \
                            local_ip2hc[IP2HC_HIT_KEY][IP2HC_TOTAL_MATCHED_FALG]
                        current_last_matched = \
                            local_ip2hc[IP2HC_HIT_KEY][IP2HC_LAST_MATCHED_FALG]
                        current_total_matched += times
                        current_last_matched += times
                        key_list.append(IP2HC_TOTAL_MATCHED_FALG)
                        set_mpmgr_dict(
                            self._ip2hc, key_list, current_total_matched
                        )
                        key_list.pop()
                        key_list.append(IP2HC_LAST_MATCHED_FALG)
                        set_mpmgr_dict(
                            self._ip2hc, key_list, current_last_matched
                        )
                        key_list.pop()
                        return 0
            else:
                key_list.append(ip_addr_part)
                if ip_addr_part in local_ip2hc:
                    local_ip2hc = local_ip2hc[ip_addr_part]
                else:
                    print(
                        "Error: can't find info for this ip %d in IP2HC"%ip_addr
                    )
                    return -1
        print("Error: can't find info for this ip %d in IP2HC" % ip_addr)
        return -1

    def get_cached_size(self):
        return len(self.cache)

    def get_cached_info(self, cache_idx):
        ip_addr = self.cache[cache_idx][CACHE_IP_ADDR_FLAG]
        hc_value = self.read_hc(ip_addr)
        return ip_addr, hc_value

    def update_cache(self, hits_bitmap):
        # Select count item to be replaced
        count = min(hits_bitmap.count(0), self.count.value - len(self.cache))
        controller_list_to_replace = []
        # scheme structure: {cache_idx: (old_entry_handle, new_ip, new_hc)}
        update_scheme = {}
        left_cache_size = CACHE_SIZE - len(self.cache)
        if DEBUG_OPTION:
            print(
                "Debug: Decide to add or replace %d cache entries ..." % count
            )
        if count <= left_cache_size:
            for i in range(count):
                controller_item = self.impact_heap.pop()
                if controller_item[IMPACT_HEAP_IMPACT_FACTOR_FLAG] == 0.0:
                    # Already in cache
                    print("Error: Impossible branch!")
                    self.impact_heap.push_direct(controller_item)
                else:
                    ip_addr = controller_item[IMPACT_HEAP_IP_ADDR_FLAG]
                    cache_idx = len(self.cache)
                    hc_value = self.read(ip_addr)
                    self.cache.append([ip_addr, cache_idx])
                    controller_item[IMPACT_HEAP_IMPACT_FACTOR_FLAG] = 0.0
                    hits_bitmap[cache_idx] = 1
                    self.impact_heap.push_direct(controller_item)
                    update_scheme[cache_idx] = \
                            (NOT_DELETE_HANDLE, ip_addr, hc_value)
        else:
            for i in range(count - left_cache_size):
                controller_list_to_replace.append(self.impact_heap.pop())
            for i in range(left_cache_size):
                controller_item = self.impact_heap.pop()
                if controller_item[IMPACT_HEAP_IMPACT_FACTOR_FLAG] == 0.0:
                    # Already in cache
                    print("Error: Impossible branch!")
                    self.impact_heap.push_direct(controller_item)
                else:
                    ip_addr = controller_item[IMPACT_HEAP_IP_ADDR_FLAG]
                    cache_idx = len(self.cache)
                    hc_value = self.read_hc(ip_addr)
                    self.cache.append([ip_addr, cache_idx])
                    controller_item[IMPACT_HEAP_IMPACT_FACTOR_FLAG] = 0.0
                    hits_bitmap[cache_idx] = 1
                    self.impact_heap.push_direct(controller_item)
                    update_scheme[cache_idx] = \
                            (NOT_DELETE_HANDLE, ip_addr, hc_value)
            for i in range(count - left_cache_size):
                controller_item = controller_list_to_replace[i]
                if controller_item[IMPACT_HEAP_IMPACT_FACTOR_FLAG] == 0.0:
                    # Already in cache
                    self.impact_heap.push_direct(controller_item)
                    continue
                cache_idx = hits_bitmap.index(0)
                cache_item = self.cache[cache_idx]
                old_ip_addr = cache_item[CACHE_IP_ADDR_FLAG]
                entry_handle = cache_item[CACHE_ENTRY_HANDLE_FLAG]
                old_ip_total_matched, old_ip_last_matched \
                        = self.read_match_times(old_ip_addr)
                new_ip_addr = controller_item[IMPACT_HEAP_IP_ADDR_FLAG]
                if old_ip_addr == new_ip_addr:
                    # Already in cache
                    self.impact_heap.push_direct(controller_item)
                    continue
                new_ip_hc_value = self.read_hc(new_ip_addr)
                # Push new item from controller into cache
                cache_item[CACHE_IP_ADDR_FLAG] = new_ip_addr
                self.cache[cache_idx] = cache_item
                # Set the impact factor of thoes pushed into cache to 0
                controller_item[IMPACT_HEAP_IMPACT_FACTOR_FLAG] = 0.0
                self.impact_heap.push_direct(controller_item)
                update_scheme[cache_idx] = \
                        (entry_handle, new_ip_addr, new_ip_hc_value)
                # update_scheme[cache_idx] = \
                    # (old_ip_addr, new_ip_addr, self.hc_value[new_ip_ip2hc_idx])
                # Set the impact factor of those from cache to normal
                self.impact_heap.update(
                    old_ip_addr, old_ip_total_matched, old_ip_last_matched
                )
        return update_scheme

    def reset_last_matched(self):
        for key_list in self.key_list_set:
            key_list.append(IP2HC_LAST_MATCHED_FALG)
            set_mpmgr_dict(self._ip2hc, key_list, 0)
            key_list.pop()

    def update_entry_handle_in_cache(self, cache_idx, entry_handle):
        cache_item = self.cache[cache_idx]
        cache_item[CACHE_ENTRY_HANDLE_FLAG] = entry_handle
        self.cache[cache_idx] = cache_item

class TCP_Session:
    def __init__(self):
        self.state = array('B', [0 for ip_addr in range(IP_SPACE_SIZE)])
        self.seq_number = array('I', [0 for ip_addr in range(IP_SPACE_SIZE)])
        print("TCP State List Size: %d" % sys.getsizeof(self.state))
        print("TCP SEQ Number List Size: %d" % sys.getsizeof(self.seq_number))

    def read(self, ip_addr):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        # Temporary method
        ip_addr = ip_addr & (IP_SPACE_SIZE - 1)
        return self.state[ip_addr], self.seq_number[ip_addr]

    def update(self, ip_addr, state, seq_number):
        if type(ip_addr) == str:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
        # Temporary method
        ip_addr = ip_addr & (IP_SPACE_SIZE - 1)
        self.state[ip_addr] = state
        self.seq_number[ip_addr] = seq_number

def set_mpmgr_dict(mpmgr_dict, key_list, value):
    # sub_dict is to resolve the problem of nest dict in multiprocessing
    if len(key_list) == 1:
        mpmgr_dict[key_list[0]] = value
    elif len(key_list) == 2:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 3:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 4:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 5:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 6:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 7:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 8:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 9:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 10:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]]\
                [key_list[9]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 11:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]]\
                [key_list[9]][key_list[10]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 12:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]]\
                [key_list[9]][key_list[10]][key_list[11]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 13:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]]\
                [key_list[9]][key_list[10]][key_list[11]][key_list[12]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 14:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]]\
                [key_list[9]][key_list[10]][key_list[11]][key_list[12]]\
                [key_list[13]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 15:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]]\
                [key_list[9]][key_list[10]][key_list[11]][key_list[12]]\
                [key_list[13]][key_list[14]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 16:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]]\
                [key_list[9]][key_list[10]][key_list[11]][key_list[12]]\
                [key_list[13]][key_list[14]][key_list[15]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    elif len(key_list) == 17:
        sub_dict = mpmgr_dict[key_list[0]]
        sub_dict[key_list[1]][key_list[2]][key_list[3]][key_list[4]]\
                [key_list[5]][key_list[6]][key_list[7]][key_list[8]]\
                [key_list[9]][key_list[10]][key_list[11]][key_list[12]]\
                [key_list[13]][key_list[14]][key_list[15]][key_list[16]] = value
        mpmgr_dict[key_list[0]] = sub_dict
    else:
        print("Error: The key_list is too long!")
