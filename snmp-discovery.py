#!/usr/bin/env python2
#copyright curesec gmbh 2014, ping@curesec.com
#

import argparse
import netaddr
import Queue
import threading

from pysnmp.entity.rfc3413.oneliner import cmdgen


myQueue = Queue.Queue()
myLock = threading.Lock()


class SNMP_SCAN(threading.Thread):
	def run(self):
		while True:
			ip, port, version, timeout, retries, verbose = myQueue.get()
			self.start_snmp_scan(ip, port, version, timeout, retries, verbose)
			myQueue.task_done()

	def start_snmp_scan(self, ip, port, version, timeout, retries, verbose):
		if verbose:
			myLock.acquire()
			print "Scanning: %s:%d v%d" % (ip, port, version)
			myLock.release()
		successful = snmp_scan(ip, port, version, timeout, retries, verbose)
		if successful:
			myLock.acquire()
			print "SNMP v%d found on %s:%d" % (version, ip, port)
			myLock.release()
		else:
			if verbose:
				myLock.acquire()
				print "No reply from %s:%d v%d" % (ip, port, version)
				myLock.release()

# returns True if the SNMP agent answers our get request
# returns False otherwise
def snmp_scan(ip, port, version, timeout, retries, verbose):
	cmdGen = cmdgen.CommandGenerator()

	if version == 1:
		community_string = "public"
		authentication_token = cmdgen.CommunityData(community_string, mpModel = 0)
	elif version == 2:
		community_string = "public"
		authentication_token = cmdgen.CommunityData(community_string, mpModel = 1)
	else: # version 3
		# picking an implausible username to produce an "unknownUserName" response
                username = "mfxgfwvhxcrqeejolnhjskie"
		authentication_token = cmdgen.UsmUserData(username)

	errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
		authentication_token,
		cmdgen.UdpTransportTarget((ip, port), timeout = timeout, retries = retries),
		cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0)
	)
		
	if errorIndication:
		if verbose:
			myLock.acquire()
			print "%s" % (errorIndication)
			myLock.release()
		if version == 3 and errorIndication == "unknownUserName":
			return True
		else:
			return False
	elif errorStatus:
		if verbose:
			myLock.acquire()
			print "%s" % (errorStatus)
			myLock.release()
		return False
	else:
		if verbose:
			for name, val in varBinds:
				myLock.acquire()
				print "%s = %s" % (name.prettyPrint(), val.prettyPrint())
				myLock.release()
		return True









def init_snmp_scan(ip, port, args):
	timeout = args.timeout
	retries = args.retries
	verbose = args.verbose
	if args.version == None:
		#run_snmp_scan(ip, port, 1, timeout, retries, verbose)
		#run_snmp_scan(ip, port, 2, timeout, retries, verbose)
		#run_snmp_scan(ip, port, 3, timeout, retries, verbose)
		myQueue.put((ip, port, 1, timeout, retries, verbose))
		myQueue.put((ip, port, 2, timeout, retries, verbose))
		myQueue.put((ip, port, 3, timeout, retries, verbose))
	else:
		if args.version != 1 and args.version != 2 and args.version != 3:
			print "Error: version must either be 1, 2 or 3."
			return
		version = args.version
		#run_snmp_scan(ip, port, version, timeout, retries, verbose)
		myQueue.put((ip, port, version, timeout, retries, verbose))



def parse_ports(ip, args):
	if args.port:
		run_snmp_scan_init(ip, args.port, args)
	elif args.portrange:
		port1 = int(args.portrange.split("-")[0])
		port2 = int(args.portrange.split("-")[1])
		for port in range(port1, port2 + 1):
			run_snmp_scan_init(ip, port, args)
	elif args.portfile:
		portfile = open(args.portfile, "r")
		for port in portfile:
			port = port.strip()
			port = int(port)
			run_snmp_scan_init(ip, port, args)
		portfile.close()
	else:
		init_snmp_scan(ip, 161, args)



def parse_ips(args):
	if args.hostname:
		try:
			ip = socket.gethostbyname(args.hostname)
		except socket.error as e:
			if args.verbose:
				print "Socket error: %s" % e
			return
		parse_ports(ip, args)
	elif args.ip:
		parse_ports(args.ip, args)
	elif args.ipnetwork:
		ipnetwork = netaddr.IPNetwork(args.ipnetwork)
		for ip in ipnetwork:
			parse_ports(str(ip), args)
	elif args.iprange:
		ip1 = args.iprange.split("-")[0]
		ip2 = args.iprange.split("-")[1]
		iprange = netaddr.IPRange(ip1, ip2)
		for ip in iprange:
			parse_ports(str(ip), args)
	elif args.ipfile:
		ipfile = open(args.ipfile, "r")
		for ip in ipfile:
			ip = ip.strip()
			parse_ports(ip, args)
		ipfile.close()


def init(args):
	for i in range(args.threads):
		worker_thread = SNMP_SCAN()
		worker_thread.setDaemon(True)
		worker_thread.start()
	parse_ips(args)
	myQueue.join()

def main():
	parser_description = 	"Testable SNMP version are SNMPv1, SNMPv2c and SNMPv3.\n" +\
				"If no version is specified, all three versions are tested.\n" +\
				"Version 1 and version 2 are tested by using the community string \"public\".\n" +\
				"An SNMP server will not send a reply if that community string is invalid,\n" +\
				"resulting in inaccurate results. A brute force attempt on the community string\n" +\
				"can be attempted to verify its existence.\n" +\
				"On the other hand, SNMP Version 3 should always return \"user not found\".\n" +\
				"There appears to be a bug in pysnmp: For SNMP version 3, picking\n" +\
 				"a retries value of either 0 and 1 might result in an infinite loop."
	parser = argparse.ArgumentParser(description = parser_description, formatter_class=argparse.RawTextHelpFormatter)
	group1 = parser.add_mutually_exclusive_group(required=True)
	group1.add_argument("-hostname", action="store", dest="hostname", help="e.g. example.com")
	group1.add_argument("-ip", action="store", dest="ip", help="e.g. 192.168.0.1")
	group1.add_argument("-ipnetwork", action="store", dest="ipnetwork", help="e.g. 192.168.0.0/24")
	group1.add_argument("-iprange", action="store", dest="iprange", help="e.g. 192.168.0.1-192.168.0.254")
	group1.add_argument("-ipfile", action="store", dest="ipfile", help="e.g. ips.txt")
	group2 = parser.add_mutually_exclusive_group(required=False)
	group2.add_argument("-port", action="store", dest="port", type=int, help="default 161")
	group2.add_argument("-portrange", action="store", dest="portrange", help="e.g. 1-1000")
	group2.add_argument("-portfile", action="store", dest="portfile", help="e.g. ports.txt")
	parser.add_argument("-version", action="store", dest="version", type=int, required=False, help="(1 | 2 | 3)")
	parser.add_argument("-timeout", action="store", dest="timeout", type=int, default=3, required=False, help="default 3")
	parser.add_argument("-retries", action="store", dest="retries", type=int, default=2, required=False, help="default 2")
	parser.add_argument("-threads", action="store", dest="threads", type=int, default=1, required=False, help="default 1")
	parser.add_argument("-v", action="store_true", dest="verbose", default=False, required=False)
	args = parser.parse_args()

	init(args)


if __name__ == '__main__':
	main()
