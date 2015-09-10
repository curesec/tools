#!/usr/bin/env python2
#
# Example code for generating random ips with targetlib
# Marco Lux <marco.lux@curesec.com>
#
# ./generateRandom.py 10
# 100.206.1.x
# 38.198.240.x
# 79.230.61.x
# 29.211.199.x
# 76.98.143.x
# 131.238.68.x
# 212.190.155.x
# 113.24.152.x
# 248.183.28.x
# 51.254.4.x
# Done


import sys
import targetlib

def usage():
	print '%s <ip count>' % (sys.argv[0])

if len(sys.argv)<2:
	usage()
	exit(1)

count = int(sys.argv[1])


tl = targetlib.targetlib()
tl.generate_random_ip(count)

while tl.tgt_q.qsize() != 0:
	tgt = tl.tgt_q.get()
	print tgt

print 'Done'
