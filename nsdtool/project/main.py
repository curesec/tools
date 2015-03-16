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

import os
import sys
import argparse
import binascii

import configreader
import argumentparser
import nsdpsniffer
import nsdpdiscover
import nsdpsetpassword
import nsdprebootdevice
import nsdppasswordbruteforce
import network
import targets

"""
NSPD discover/sniffer main class implementation
"""

class NSDP(object):

    def __init__(self):
        """Get command line arguments to check which mode is enabled

        """
        args = argumentparser.ArgumentParser().parse()
        pws = list()
        
        config = configreader.ConfigReader().read()
        
        self.source_port = int(config['NSDP']['SourcePort'])
        self.dest_port = int(config['NSDP']['DestPort'])
        self.interface = config['NSDP']['Interface']
        self.dest_ip = config['NSDP']['DestIP']
        self.delay = config.getfloat('NSDP','Delay')
        self.network = network.Network(self.interface, self.dest_ip, 
                self.source_port, self.dest_port)
        self.quiet = False

        if args['sniffer'] == True:
            self.mode = 'sniffer'
        elif args['discover'] == True:
            self.mode = 'discover'
            if args["target"] is not None:
                self.discovermode = "target"
                self.target = args["target"][0]
                self.fd = None
            else:
                self.discovermode = "targetlist"
                self.fd = args["targetlist"][0]

            if args["delay"] is not None:
                self.delay = args["delay"][0]
        elif args['setpassword'] == True:
            self.mode = 'setpassword'
            self.oldpassword = args["currentpassword"][0]
            self.newpassword = args["newpassword"][0]
            self.macaddress = args["macaddress"][0]
        elif args['reboot'] == True:
            self.mode = 'reboot'
            self.password = args['password'][0]
            self.macaddress = args['macaddress'][0]
        elif args['bruteforce'] is not None:
            self.mode = 'bruteforce'
            self.fd = args['bruteforce'][0]
            self.password = args['newpassword'][0]
            self.macaddress = args['macaddress'][0]

        if args['quiet'] == True:
            self.quiet = True

    def start(self):

        if not hasattr(self, "mode"):
            print("please specifiy a mode: -s, -d, -sp, -bf, -r")
            sys.exit(0)

        if self.mode == 'sniffer':
            sniffer = nsdpsniffer.NSDPSniffer(self.dest_port)
            sniffer.start_sniffer()
        elif self.mode == 'discover':
            if self.fd is not None:
                discover = nsdpdiscover.NSDPDiscover(self.network, self.fd, None, self.delay, self.quiet)
            else:
                discover = nsdpdiscover.NSDPDiscover(self.network, None, self.target, self.delay, self.quiet)
            discover.start_discover()
        elif self.mode == 'setpassword':
            setpassword = nsdpsetpassword.NSDPSetPassword(self.network, 
                    self.oldpassword, self.newpassword, self.macaddress)
            setpassword.start_set_password()
        elif self.mode == 'reboot':
            rebootdevice = nsdprebootdevice.NSDPRebootDevice(self.network, 
                    self.password, self.macaddress)
            rebootdevice.start_reboot_device()
        elif self.mode == 'bruteforce':
            bruteforce = nsdppasswordbruteforce.NSDPPasswordBruteForce(
                    self.network, self.dest_port, self.password, self.macaddress, self.fd, self.quiet)
            bruteforce.start_password_bruteforce()
 
nsdp = NSDP()
nsdp.start()
