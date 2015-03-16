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
import threading
import struct
import logging
import sys
import re
from random import shuffle


# type of targets
TYPE_IP = 0x01
TYPE_RANGE = 0x02
TYPE_MASK = 0x03

class Targets():

    def __init__(self, hosts, quiet):
        self.hosts = []
        self.hosts.append(hosts)
        self.quiet = quiet

    def generateTargets(self):
        """ set up the queue with targets. a target is a tuple
            (ip, port). function resolves hostnames to ips. result 
            is shuffled.
        """
        targets = []

        count, targets_pre = self.prepareTargets() 
        self.generateTargetList(targets_pre, targets)

        return count, targets 

    def getNetmask(self, prefix, bit):
        """ gets a prefix in dotted notation and a bit to indicated netmask.
            returns start and end ip of netrange as long(!)
        """
        prefix = struct.unpack(">I",socket.inet_aton(prefix))[0]

        shift = 32-bit
        start = prefix >> shift << shift

        mask = (1 << shift) - 1
        end = start | mask

        return start,end

    def prepareTargets(self):
        """ extracts ip-ranges, netmasks und single ips or domains from host
            queue and puts them into a list; counts total no of targets.
        """
        pre_targets = []        
        count = 0
        for host in self.hosts:
            entry = None
            if not entry and  "-" in host:
                h = host.split("-")
                ip_start = h[0]    
                ip_end = h[1]    

                if self.isIP(ip_start) and self.isIP(ip_end):
                    entry = TYPE_RANGE, (ip_start, ip_end)

                    start_long = struct.unpack(">I",socket.inet_aton(ip_start))[0]
                    end_long = struct.unpack(">I",socket.inet_aton(ip_end))[0]
                    count += (end_long - start_long)            

            if not entry and "/" in host:
                h = host.split("/")
                ip = h[0]
                try:
                    bit = int(h[1])
                except ValueError:
                    continue
                                
                if self.isIP(ip):
                    entry = TYPE_MASK, (ip, bit)
                    count += pow(2,32-bit)


            if not entry and (self.isIP(host) or self.isDomain(host)):
                entry = TYPE_IP, host
                count += 1

            if entry:
                pre_targets.append(entry)

        shuffle(pre_targets)
        return count, pre_targets

    def isIP(self, totest):
        """ returns whether input is an ip """
        return True if not re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"\
                        "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",totest) == None else False

    def isDomain(self, totest):
        """ returns whethter input is a domain """
        return True if not re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$",\
                            totest) == None else False

    def generateTargetList(self, prepared, _targets):
        """ create a list with all targets """

        for t, entry in prepared:

            if t == TYPE_MASK:
                net, bit = entry
                start, end = self.getNetmask(net,bit)
                self.iterateOverTargets(start, end, _targets)

            elif t == TYPE_RANGE:
                start_dotted, end_dotted = entry
                start = struct.unpack(">I", socket.inet_aton(start_dotted))[0]
                end = struct.unpack(">I", socket.inet_aton(end_dotted))[0]
                self.iterateOverTargets(start, end, _targets)

            elif t == TYPE_IP:
                if self.isIP(entry):
                    ip = entry

                _targets.append(ip)

            else:
                continue

    def iterateOverTargets(self, start, end, targets):
        """ iterates ip from start to end and appends them to targets """
        ip = start
        _targets = []
        while ip <= end:
            if self.quiet == False: 
                sys.stdout.write("\rgenerating targets: %i" % len(targets))
                sys.stdout.flush()
      
            ip_dotted = socket.inet_ntoa(struct.pack(">I", ip))
            targets.append(ip_dotted)
            ip += 1
