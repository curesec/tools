#!/usr/bin/env python2
#
# ./$0 1.1.1.1 1.1.1.5

import sys
import targetlib

s = sys.argv[1]
e = sys.argv[2]

tl = targetlib.targetlib()
tl.generate_target_range(s,e)
print 'target list has %d ips' % (tl.tgt_q.qsize())
