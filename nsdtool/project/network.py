#!/usr/bin/env python3
#The MIT License (MIT)
#
#Copyright (c) 2014 Curesec GmbH <https://www.curesec.com>
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

import socket
import sys
import fcntl
import struct

from struct import *

class Network():

    def __init__(self, interface, dest_ip, source_port, dest_port):
        self.interface = interface
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.source_ip = self.get_ip_address(self.interface)

    def set_dest_address(self, dest_ip):
        self.dest_ip = dest_ip

    def get_ip_address(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            ip = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(), 
                0x8915, 
                struct.pack('256s', ifname[:15].encode('utf-8')))[20:24])
        except OSError:
            print("Wrong interface name: " + ifname + "\ncheck config.ini")
            sys.exit(0)
        
        return ip


    def checksum(msg):
        s = 0

        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i+1] << 8 )
            s = s + w
            s = (s>>16) + (s & 0xffff);
            s = s + (s >> 16);
            s = ~s & 0xffff

        return s

    def generate_ip_header(self, protocol):
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  
        ip_id = 36013
        ip_frag_off = 0
        ip_ttl = 255

        if protocol == "TCP":
            ip_proto = socket.IPPROTO_TCP
        elif protocol == "UDP":
            ip_proto = socket.IPPROTO_UDP

        ip_check = 0   
        ip_saddr = socket.inet_aton(self.source_ip)
        ip_daddr = socket.inet_aton(self.dest_ip)
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, 
                ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, 
                ip_daddr)

        return ip_header

    def generate_udp_header(self, source_port, dest_port, length, checks, user_data):
        udp_source = source_port
        udp_dest = dest_port
        udp_length = length
        udp_checksum = 0

        udph = pack('!HHHH', udp_source, udp_dest, udp_length, udp_checksum)

        # pseudo header fields
        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP
        udp_length = len(udph) + len(user_data)

        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, 
                protocol, udp_length)
        psh = psh + udph + user_data

        sum = 0

        for i in range(0, len(psh), 2):
            if i+1 >= len(psh):
                sum += (psh[i]) & 0xFF
            else:
                w = (((psh[i] << 8) & 0xFF00) + ((psh[i+1]) & 0xFF))
                sum += w

        while (sum >> 16) > 0:
            sum = (sum & 0xFFFF) + (sum >> 16)

        sum = ~sum
        udp_checksum = sum & 0xFFFF
        udp_header = pack('!HHHH', udp_source, udp_dest, udp_length, 
                udp_checksum)
    
        return udp_header

    def init_socket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 
                    socket.IPPROTO_RAW)
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg))
            sys.exit()

        return s
