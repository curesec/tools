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
import select

from struct import *

class NSDPSniffer():

    def __init__(self, port):
        self.port = port

    def eth_addr(self, a) :
      b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0] , a[1] , a[2], a[3], a[4] , a[5])
      
      return b

    def start_sniffer(self):
        """Start NSDP sniffer. 
        
        .. note::
            s1 and s2 are required due to a problem handling all incoming UDP packets.

        """
        s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s1.bind(('0.0.0.0', self.port))
        s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        s2.bind(('0.0.0.0', self.port))

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
         
                ttl = iph[5]
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
                        print('Version : ' + str(version) + 
                                ' IP Header Length : ' + str(ihl) + ' TTL : ' + 
                                str(ttl) + ' Protocol : '   + str(protocol) + 
                                ' Source Address : ' + str(s_addr) + 
                                ' Destination Address : ' + str(d_addr))
                        print('Source Port : ' + str(source_port) + 
                                ' Dest Port : ' + str(dest_port) + ' Length : ' + 
                                str(length) + ' Checksum : ' + str(checksum))

                        h_size = eth_length + iph_length + udph_length
                        data_size = len(packet) - h_size
                        data = packet[h_size:]

                        print("protocol: " + chr(data[10]) + chr(data[11]) + 
                                chr(data[12]) + chr(data[13]))
                        print("device: " + chr(data[22]) + chr(data[23]) + 
                                chr(data[24]) + chr(data[25]) + chr(data[26]) + 
                                chr(data[27]) + chr(data[28]) + chr(data[29]))
                        print("mac: " + self.eth_addr(data[0:6]))
                        print("firmware version: " + chr(data[104]) + 
                                chr(data[105]) + chr(data[106]) + 
                                chr(data[107]) + chr(data[108]) + 
                                chr(data[109]) + chr(data[110]) + 
                                chr(data[111]))
                        print("default gateway: " + str(data[74]) + "." + 
                                str(data[75]) + "." + str(data[76]) + "." + 
                                str(data[77]))
                        print("switch ip: " + str(data[58]) + "." + 
                                str(data[59]) + "." + str(data[60]) + "." + 
                                str(data[61]))
                        print("subnet mask: " + str(data[66]) + "." + 
                                str(data[67]) + "." + str(data[68]) + "." + 
                                str(data[69]))
