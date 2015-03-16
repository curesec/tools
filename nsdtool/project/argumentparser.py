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
#

"""NSDP sniffer/discover argument parser implementation
"""

import sys
import argparse

class ArgumentParser():
    """Parse Command Line Arguments"""
    def __init__(self):
        self._args = [] 

    def parse(self):
        """Parse command line arguments

        Returns:
            args : Command line arguments

        """
        parser = argparse.ArgumentParser(
                description='Netgear Switch Discovery Protocol - 0.01a')

        parser.add_argument('-s', '--sniffer', 
                help='Start the program in sniffer mode', required=False, 
                action='store_true')
        parser.add_argument('-d', '--discover', 
                help='Start the program in discover mode', required=False, 
                action='store_true')
        parser.add_argument('-sp', '--setpassword', 
                help='Set the password of the device (-cp, -np, -m required)',
                required=False, action='store_true')
        parser.add_argument('-cp', '--currentpassword', 
                help="Current device password", required=False, nargs=1)
        parser.add_argument('-np', '--newpassword', 
                help='New device password string', required=False, nargs=1)
        parser.add_argument('-r', '--reboot', help='Reboot the device', 
                    required=False, action='store_true')
        parser.add_argument('-bf', '--bruteforce', nargs=1, 
                type=argparse.FileType('r'), default=None, 
                help="Start bruteforce attack, (-np, -m required)")
        parser.add_argument('-p', '--password', help='Password string', 
                    required=False, nargs=1)
        parser.add_argument('-m', '--macaddress', 
                help='MAC address in format xx:xx:xx:xx:xx:xx', required=False, 
                nargs=1)
        parser.add_argument('-t', '--target', help='Discover message target', 
                required=False, nargs=1)
        parser.add_argument('-tl', '--targetlist', nargs=1, 
                type=argparse.FileType('r'), default=None, 
                help="Discover message target list file input")
        parser.add_argument('-de', '--delay', help='UDP transmission delay', 
                type=float, required=False, nargs=1)
        parser.add_argument('-q', '--quiet', 
                help='Start the program in quiet mode', required=False, 
                action='store_true')

        if len(sys.argv)==1:
            parser.print_help()
            sys.exit(1)

        self._args = vars(parser.parse_args())

        if self._args["discover"] == True:
            if ((self._args["target"] is None) and
                (self._args["targetlist"] is None)):
                print("""Error: -d (--discover) requires either -t (--target) 
                      or -tl (--targetlist)""")
                sys.exit(0)
            if ((self._args["target"] is not None) and
                (self._args["targetlist"] is not None)):
                print("""Error: -d (--discover) requires either -t (--target) 
                      or -tl (--targetlist)""")
                sys.exit(0)

        if self._args["setpassword"] == True:
            if ((self._args["currentpassword"] is None) or 
               (self._args["newpassword"] is None) or 
               (self._args["macaddress"] is None)):
                print("""Error: -sp (--setpassword) requires options -cp 
                      (--currentpassword), -np (--newpassword), -m 
                      (--macaddress)""")
                sys.exit(0)
            elif ((len(self._args["newpassword"][0]) < 8)):
                print("new password to short, minimum 8 characters")
                sys.exit(0)

   
        if self._args["reboot"] == True:
            if ((self._args["password"] is None) or
                (self._args["macaddress"] is None)):
                print("""Error: -r (--reboot) requires options -p (--password), 
                      -m (--macaddress)""")
                sys.exit(0)

        if self._args["bruteforce"] is not None:
            if ((self._args["newpassword"] is None) or
                (self._args["macaddress"] is None)):
                print("""Error: -bf (--bruteforce) requires options -np 
                      (--newpassword), -m (--macaddress)""")
                sys.exit(0)
            elif ((len(self._args["newpassword"][0]) < 8)):
                print("new password to short, minimum 8 characters")
                sys.exit(0)

        return self._args
