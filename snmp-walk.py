#!/usr/bin/env python2
#copyright curesec gmbh ping@curesec.com

# http://pysnmp.sourceforge.net/examples/current/v3arch/oneliner/manager/cmdgen/getnext-v1.html

import argparse

from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()


def snmp_walk(ip, port, version, timeout, retries, oid, n, maxrows, authentication):
	errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
		authentication,
		cmdgen.UdpTransportTarget((ip, port),
		timeout = timeout, retries = retries),
		oid,
		lookupNames=not n, lookupValues=not n,
		maxRows=maxrows
	)

	if errorIndication:
		print "Error: %s" % errorIndication
	else:
		if errorStatus:
			print('Error: %s at %s' % (
				errorStatus.prettyPrint(),
				errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
				)
			)
		else:
			for varBindTableRow in varBindTable:
				for name, val in varBindTableRow:
					print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))

def init(args):
	ip = args.ip
	port = args.port
	version = args.version
	timeout = args.timeout
	retries = args.retries
	oid = args.oid
	n = args.n
	maxrows = args.maxrows

	if version != 1 and version != 2 and version != 3:
		print "Error: Version must be either 1, 2 or 3"
		return

	if version == 1 or version == 2:
		if not args.communitystring:
			print "Error: community string required."
			return
		community_string = args.communitystring
		if version == 1:
			authentication =  cmdgen.CommunityData(community_string, mpModel = 0)
		elif version == 2:
			authentication =  cmdgen.CommunityData(community_string, mpModel = 1)
	else:
		auth_protocols = { "MD5": cmdgen.usmHMACMD5AuthProtocol, "SHA": cmdgen.usmHMACSHAAuthProtocol}
		priv_protocols = { "DES": cmdgen.usmDESPrivProtocol, "3DES": cmdgen.usm3DESEDEPrivProtocol,
					"AES128": cmdgen.usmAesCfb128Protocol, "AES192": cmdgen.usmAesCfb192Protocol,
					"AES256": cmdgen.usmAesCfb256Protocol }
		if not args.username:
			print "Error: Username required."
			return
		username = args.username
		if not args.auth_password:
			authentication = cmdgen.UsmUserData(username)
		else:
			auth_password = args.auth_password
			if args.auth_protocol:
				auth_protocol = auth_protocols[args.auth_protocol]
			else:
				auth_protocol = auth_protocols["MD5"]
			if not args.priv_password:
				authentication = cmdgen.UsmUserData(username, auth_password, authProtocol = auth_protocol)
			else:
				priv_password = args.priv_password
				if args.priv_protocol:
					priv_protocol = priv_protocols[args.priv_protocol]
				else:
					priv_protocol = priv_protocols["DES"]
				authentication = cmdgen.UsmUserData(username, auth_password, priv_password, authProtocol = auth_protocol, privProtocol = priv_protocol)
	snmp_walk(ip, port, version, timeout, retries, oid, n, maxrows, authentication)
			





def main():
	parser_description = 	"For SNMP version 1 and 2 a community string is needed\n" +\
				"For SNMP version 3 a username is need. In addition to the username,\n" +\
				"an authentication password or authentication/privary passwords\n" +\
				"can be provided.\n" +\
				"pysnmp does not produce any output until it is finished. So be patient\n" +\
				"or use -oid or -maxrows to reduce ammount of OIDs to retrieve.\n" +\
				"There appears to be a bug in pysnmp: For SNMP version 3, picking\n" +\
				"a retries value of either 0 and 1 might result in an infinite loop."
	parser = argparse.ArgumentParser(description = parser_description, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-ip", action="store", dest="ip", required=True, help="e.g. 192.168.0.1")
	parser.add_argument("-port", action="store", dest="port", required=False, type=int, default=161, help="default 161")
	parser.add_argument("-version", action="store", dest="version", type=int, required=True, help="(1 | 2 | 3)")
	group1 = parser.add_mutually_exclusive_group(required=True)
	group1.add_argument("-communitystring", action="store", dest="communitystring", help="version 1 and 2")
	group1.add_argument("-username", action="store", dest="username", help="version 3")
	parser.add_argument("-a", action="store", dest="auth_password", required=False, help="optional")
	parser.add_argument("-A", action="store", dest="auth_protocol", required=False, help="optional; MD5 (default), SHA")
	parser.add_argument("-p", action="store", dest="priv_password", required=False, help="optional")
	parser.add_argument("-P", action="store", dest="priv_protocol", required=False, help="optional; DES (default), 3DES, AES128, AES192, AES256")
	parser.add_argument("-timeout", action="store", dest="timeout", type=int, default=3, required=False, help="default 3")
	parser.add_argument("-retries", action="store", dest="retries", type=int, default=2, required=False, help="default 2. Do not use 0 or 1 due to a bug in pysnmp.")
	parser.add_argument("-oid", action="store", dest="oid", default="1.3.6.1.2.1", required=False, help="default 1.3.6.1.2.1. Specify the subtree to enumerate, 1.3 for all")
	parser.add_argument("-n", action="store_true", dest="n", default=False, required=False, help="print OIDs numerically")
	parser.add_argument("-maxrows", action="store", dest="maxrows", type=int, default=0, required=False, help="default 0. Limit the results")
	args = parser.parse_args()

	init(args)


if __name__ == '__main__':
	main()
