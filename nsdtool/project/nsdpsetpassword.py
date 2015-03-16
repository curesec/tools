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
import binascii

import network

from struct import *

"""NSDP Discover class
    :platform: Linux
"""

class NSDPSetPassword():
    
    def __init__(self, network, oldpassword, newpassword, macaddress):
        self.network = network
        self.oldpassword = oldpassword
        self.newpassword = newpassword
        self.macaddress = macaddress

    def start_set_password(self):
        s = self.network.init_socket()
        
        packet = '';

        ip_header = self.network.generate_ip_header("UDP")
        udp_header, password_frame = self.generate_set_password_packet()
        packet = ip_header + udp_header + password_frame

        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        s.sendto(packet, (self.network.dest_ip , 0 ))


    def generate_set_password_packet(self):
        xor_bytes = bytes( [0x4e, 0x74, 0x67, 0x72,
                            0x53, 0x6d, 0x61, 0x72,
                            0x74, 0x53, 0x77, 0x69,
                            0x74, 0x63, 0x68, 0x52,
                            0x6f, 0x63, 0x6b, 0x4e]) 
      
        oldpassword = self.oldpassword.encode("utf-8")
        newpassword = self.newpassword.encode("utf-8")
        oldpassword_xor = bytes()
        newpassword_xor = bytes()
        oldpassword_len = pack("!B",len(self.oldpassword))
        newpassword_len = pack("!B",len(self.newpassword))

        mac = binascii.unhexlify(self.macaddress.replace(':', ''))

        for i in range(0,len(oldpassword)):
            oldpassword_xor += pack("!B", oldpassword[i] ^ xor_bytes[i])

        for i in range(0,len(newpassword)):
            newpassword_xor += pack("!B",newpassword[i] ^ xor_bytes[i])

        password_frame = bytes([0x01,0x03,0x00,0x00,0x00,0x00,
            0x00,0x00,0x08,0x00,0x27,0x47,0x56,0x16])
        password_frame += mac
        password_frame += bytes([0x00,0x00,0x00,0x0d,0x4e,0x53,0x44,0x50,0x00,
            0x00,0x00,0x00,0x00,0x0a,0x00])
        password_frame += oldpassword_len
        password_frame += oldpassword_xor
        password_frame += bytes([0x00,0x09,0x00])
        password_frame += newpassword_len
        password_frame += newpassword_xor
        password_frame += bytes([0xff,0xff,0x00,0x00])

        password_frame_length = 52 + len(self.oldpassword) + len(self.newpassword)

        udp_header = self.network.generate_udp_header(self.network.source_port, 
                self.network.dest_port, password_frame_length, 
                0, password_frame)

        return udp_header, password_frame

