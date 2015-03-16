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

import network
import targets

from struct import *
from time import sleep

"""NSDP Discover class
    :platform: Linux

"""

class NSDPDiscover():
    
    def __init__(self, network, fd, target, delay, quiet):
        self.network = network
        self.fd = fd
        self.quiet = quiet
        self.targets = targets.Targets(target, self.quiet)
        self.delay = delay

        if self.fd is not None:
            self.targets.hosts = self.fd.read().splitlines()

        self.targetcount, self.targetlist = self.targets.generateTargets()

    def start_discover(self):
        s = self.network.init_socket()
        
        for i in range(0,len(self.targetlist)):
           
            self.network.dest_ip = self.targetlist[i]
            packet = '';

            ip_header = self.network.generate_ip_header("UDP")
            udp_header, discover_data = self.generate_discover_packet()
            packet = ip_header + udp_header + discover_data
            
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
            s.sendto(packet, (self.network.dest_ip , 0 ))

            sleep(self.delay)

    def generate_discover_packet(self):
        discover_data = bytes([0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x08,
            0x00,0x27,0x47,0x56,0x16,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x03,0x4e,0x53,0x44,0x50,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
            0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,
            0x00,0x05,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x07,0x00,0x00,0x00,
            0x08,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x0d,
            0x00,0x00,0x00,0x0e,0x00,0x00,0x00,0x0f,0x00,0x00,0xff,0xff,0x00,
            0x00])


        udp_header = self.network.generate_udp_header(self.network.source_port, self.network.dest_port, 96, 
                0, discover_data)

        return udp_header, discover_data
