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


import configparser

import os
"""NSDP sniffer/discover config reader implementation
    :platform: Linux

"""

class ConfigReader():
    def read(self):
        
        config = configparser.ConfigParser()
        try:
            config_name = 'config.ini'
            config.read_file(open(os.path.join(os.path.dirname(__file__),config_name)))
        except FileNotFoundError:
            print("config file + " + config_name + " not found or readable")
            sys.exit(0)

        return config
