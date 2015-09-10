#!/usr/bin/env python2
#
# Example code for generating one random ip with targetlib
# Marco Lux <marco.lux@curesec.com>
#
# ./generate1Random.py
# 100.206.1.x
# Done


import sys
import targetlib

def usage():
	print '%s' % (sys.argv[0])

if len(sys.argv)<1:
	usage()
	exit(1)

tl = targetlib.targetlib()
print tl._generate_ip()
print 'Done'
