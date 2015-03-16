#!/usr/bin/env python2
#copyright 2014 curesec gmbh, ping@curesec.com
# tested with RFB 003.008
# http://www.realvnc.com/docs/rfbproto.pdf

import socket
import struct
import sys
from Crypto.Cipher import DES


# return status
# status 0 = success ("none" authentication method)
# status 1 = success (good password)
# status 2 = bad password
# status 3 = bad configuration (wrong version, wrong security type)
# status 4 = bad connection
# status 5 = too many failures
def testvnc(server, port, password, timeout, verbose):
	try:
		ip = socket.gethostbyname(server)
	except socket.error as e:
		print "%s" % e
		return 4

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((ip, port))
	except socket.error as e:
		print "Cannot connect to %s:%d" % (ip, port)
		print "%s" % e
		return 4
	print "Connected to %s:%d" % (server, port)


	# 11111
	# first, the server sends its RFB version, 12 bytes
	# more than 12 bytes if too many failures
	try:
		data = s.recv(1024)
	except socket.error as e:
		print "%s" % e
		return 4
        if verbose:
                print "Received [%d] version:\n%r" % (len(data), data)
	if len(data) > 12:
		return 5
	if data == "RFB 003.003\n":
		version = 3
	elif data == "RFB 003.007\n":
		version = 7
	elif data == "RFB 003.008\n":
		version = 8
	else:
		return 3
	print "RFB Version: 3.%d" % version



	# 22222
	# now, the client sends its RFB version, 12 bytes
	m = data
	if verbose:
		print "Sending [%d] version:\n%r" % (len(m), m)
	try:
		s.send(m)
	except socket.error as e:
		print "%s\n" % e
		return 4



	# 33333
	# now, the server sends the security type[s]
	# in version 3, the server decides the security type, 4 bytes
	# in version 3 using RealVNC, the server sends authentication type and challenge in one message, thus recv(4)
	# in version 7/8, the server sends a list of supported security types: number of security types of 1 byte followed by a list of security types of 1 byte each
	try:
		if version == 3:
			data = s.recv(4)
		else:
			data = s.recv(1024)
	except socket.error as e:
		print "%s" % e
		return 4
        if verbose:
                print "Received [%d] security type[s]:\n%r" % (len(data), data)

	if version == 3:
		security_type = struct.unpack("!I", data)[0]
		# security type 0 == Invalid
		# security type 1 == None
		# security type 2 == VNC
		if security_type == 1:
			return 0
		elif security_type != 2:
			return 3
	else:
		number_of_security_types = struct.unpack("!B", data[0])[0]
		if verbose:
			print "Number of security types: %d" % number_of_security_types
		if number_of_security_types == 0:
			# no security types supported
			return 3
		vnc_enabled = False
		for i in range(1, number_of_security_types + 1):
			if i >= len(data):
				# should not happen, but don't want to cause an exception
				break
			security_type = struct.unpack("!B", data[i])[0]
			# security type 1 = None
			# security type 2 = VNC
			# security type 16 = Tight
			# security type 18 = VNC
			# security type 19 = VeNCrypt
			# plus some more
			if security_type == 1:
				return 0
			elif security_type == 2:
				vnc_enabled = True
		if not vnc_enabled:
			print "VNC security type not supported"
			return 3



		# 44444
		# now, the client selects the VNC (2) security type, 1 byte
		m = struct.pack("!B", 2)
		if verbose:
			print "Sending [%d] security type:\n%r" % (len(m), m)
		try:
			s.send(m)
		except socket.error as e:
			print "%s\n" % e
			return 4


	# 55555
	# now, the server sends the authentication challenge, 16 bytes
	try:
		data = s.recv(16)
	except socket.error as e:
		print "%s" % e
		return 4

	challenge = struct.unpack("!16s", data)[0]
       	if verbose:
               	print "Received [%d] challenge:\n%r" % (len(challenge), challenge)



	# 66666
	# now, the client sends the response, 16 bytes
	key = calc_key(password)
	# encrypt 'challenge' using DES with 'key'
	cipher = DES.new(key, DES.MODE_ECB)
	response = cipher.encrypt(challenge)
	if verbose:
		print "Sending [%d] response:\n%r" % (len(response), response)
	try:
		s.send(response)
	except socket.error as e:
		print "%s\n" % e
		return 4


	# 77777
	# last, the server sends an ok or fail
	# 0 == OK, 1 == failed
	try:
		data = s.recv(1024)
	except socket.error as e:
		print "%s" % e
		return 4
        if verbose:
                print "Received [%d] security result:\n%r" % (len(data), data)

	result = struct.unpack("!I", data[0:4])[0]
	if result == 0:
		# good password
		return 1
	elif result == 1:
		# bad password
		return 2
	else:
		# protocol error
		return 3



def calc_key(password):
	key = password

	# first, pad the key with zeros to 8 bytes
	while len(key) < 8:
		key = key + "\x00"
	if len(key) > 8:
		key = key[:8]

	# second, flip all bytes individually
	flipped_key = ""
	for i in range(0 ,8):
		b = struct.unpack("B", key[i])[0]
		b_new = 0b00000000

		b_mask = 0b10000000
		bit = b & b_mask
		bit = bit >> 7
		b_new = b_new | bit

		b_mask = 0b01000000
		bit = b & b_mask
		bit = bit >> 5
		b_new = b_new | bit

		b_mask = 0b00100000
		bit = b & b_mask
		bit = bit >> 3
		b_new = b_new | bit

		b_mask = 0b00010000
		bit = b & b_mask
		bit = bit >> 1
		b_new = b_new | bit

		b_mask = 0b00001000
		bit = b & b_mask
		bit = bit << 1
		b_new = b_new | bit

		b_mask = 0b00000100
		bit = b & b_mask
		bit = bit << 3
		b_new = b_new | bit

		b_mask = 0b00000010
		bit = b & b_mask
		bit = bit << 5
		b_new = b_new | bit

		b_mask = 0b00000001
		bit = b & b_mask
		bit = bit << 7
		b_new = b_new | bit

		#print bin(b)
		#print bin(b_new)

		flipped_key = flipped_key + struct.pack("B", b_new)

	return flipped_key


def usage():
	print "usage: %s SERVER PORT PASSWORD [TIMEOUT [VERBOSE]]" % sys.argv[0]
	print "typical VNC ports are 5900, 5901, 5902..."

if __name__ == '__main__':
	if len(sys.argv) < 4:
		usage()
	else:
		server = sys.argv[1]
		port = int(sys.argv[2])
		password = sys.argv[3]
		timeout = 5
		if len(sys.argv) >= 5:
			timeout = int(sys.argv[4])
		verbose = False
		if len(sys.argv) >= 6 and sys.argv[5].lower() == "true":
			verbose = True

		# status 0 = success (no authentication)
		# status 1 = success (good password)
		# status 2 = bad password
		# status 3 = bad configuration (wrong version, wrong security type)
		# status 4 = bad connection
		# status 5 = too many failures
		status = testvnc(server, port, password, timeout, verbose)
		if status == 0:	
			print "\"None\" authentication method detected"
		elif status == 1:
			print "Authentication successful"
		elif status == 2:
			print "Authentication failed"
		elif status == 3:
			print "Protocol error"
		elif status == 4:
			print "Network error"
		elif status == 5:
			print "Too many failures"
