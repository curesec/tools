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

import aes

files = ["bc.py","listen.py","aes.py","bc.spec","MSVCP90.dll","MSVCR90.dll"]
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
	nKey = aes.Crypticle.generate_key_string()
	print "[*] New Key: %s" % (nKey)
	return nKey

# insert key
def insertKey(kFiles, nKey, oDir):
	for f in kFiles:
		fPath = "%s/%s" % (oDir,f)
		fw = open(fPath,'rw')
		fBuf = fw.readlines()
		for l in fBuf:
			if l.startswith('key = '):
				# find the position in fBuf
				kPos = fBuf.index(l)

				l = l.rstrip('\n')
				oKey = l.split('"')[1]
				print "[*] Found old key: %s" % (oKey)
				replaceKey = 'key = "%s"\n' % (nKey)
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
