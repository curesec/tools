#!/usr/bin/env python2
#
# simple prepare script, for easy aes key changes on AESshell
#
# TODO
# - add argparse
# - add force mode
# - add pyinstaller 
# 

import os
import sys
import time
import shutil
import hmac
import hashlib
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

files = ["bc.py","listen.py"]
kFiles = ["bc.py","listen.py"]
oDir = "aesout"

def usage():
	print "AESshell preparation tool"
	print ""

def checkFiles(files):
	ldir = os.listdir(".")
	for f in files:
		if ldir.count(f)==0:
			print "[-] Missing %s, abort!" % (f)
			sys.exit(1)
	return 0

def createOutputDir(oDir):
	if os.path.exists(oDir):
		print "[!] Warning %s already exists, i overwrite anyway" % (oDir)
#		time.sleep(1)
	else:
		os.mkdir(oDir)
	
	return

def copyFiles(files,oDir):
	for f in files:
		out = "%s/%s" % (oDir,f)
		print "[*] Copy %s to %s" % (f,out)
		shutil.copyfile(f,out)	

	
	print "[*] Copy done"

# create new key
def createKey():
	nKey = Crypticle.generate_key_string()
	print "[*] New Key: %s" % (nKey)
	return nKey

# insert key
def insertKey(kFiles, nKey, oDir):
	for f in kFiles:
		fPath = "%s/%s" % (oDir,f)
		fw = open(fPath,'rw')
		fBuf = fw.readlines()
		for l in fBuf:
			if l.startswith('\tkey = \"'):
				# find the position in fBuf
				kPos = fBuf.index(l)

				l = l.rstrip('\n')
				oKey = l.split('"')[1]
				print "[*] Found old key: %s" % (oKey)
				replaceKey = '\tkey = "%s"\n' % (nKey)
				fBuf[kPos] = replaceKey
		fw.close()
		fw = open(fPath,'w')
		newBuf = ""
		for l in fBuf:
			newBuf += l
		fw.write(newBuf)
		fw.close()
		print "[*] %s ready" % (fPath)




checkFiles(files)
createOutputDir(oDir)
copyFiles(files,oDir)
nKey=createKey()
insertKey(kFiles, nKey,oDir)
print "[*] Done"
