#!/usr/bin/env python2
#
# Example generateRange.py
# by Marco Lux <marco.lux@curesec.com>
#
#./generateRange.py 1.1.1.1 1.1.1.5
#Target list has 5 ips
#1.1.1.1
#1.1.1.2
#1.1.1.3
#1.1.1.4
#1.1.1.5
#Done
#


import sys
import targetlib

def usage():
	print '%s <startip> <endip>' % (sys.argv[0])

if len(sys.argv)<3:
	usage()
	exit(1)

s = sys.argv[1]
e = sys.argv[2]

tl = targetlib.targetlib()
tl.generate_target_range(s,e)
print 'Target list has %d ips' % (tl.tgt_q.qsize())
while tl.tgt_q.qsize() != 0:
	tgt = tl.tgt_q.get()
	print tgt

print 'Done'
