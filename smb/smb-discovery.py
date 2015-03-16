#!/usr/bin/env python2
#copyright 2014 curesec gmbh, ping@curesec.com


import argparse
import netaddr
import socket
import sys

import smb.base
from smb.SMBConnection import SMBConnection



# https://pythonhosted.org/pysmb/api/smb_SharedDevice.html
def list_smb_shares(conn, timeout):
	for share in conn.listShares(timeout):
		if share.type == smb.base.SharedDevice.DISK_TREE:
			share_type_name = "Disk"
		elif share.type == smb.base.SharedDevice.PRINT_QUEUE:
			share_type_name = "Printer"
		elif share.type == smb.base.SharedDevice.COMM_DEVICE:
			share_type_name = "Comm Device"
		elif share.type == smb.base.SharedDevice.IPC:
			share_type_name = "IPC"
		else:
			# should not happen
			share_type_name = ""
		print "share: %s" % share.name
		print "   comments: %s" % share.comments
		print "   type: %s" % share_type_name
		print "   isSpecial: %s" % share.isSpecial
		print "   isTemporary: %s" % share.isTemporary





def smb_scan(ip, port, list_shares, timeout, verbose):
	# empty username and password for null session
	username = ""
	password = ""
	client_name = "client"
	server_name = ip
	if port == 445:
		is_direct_tcp = True
	else:
		is_direct_tcp = False
	try:
		# def __init__(self, username, password, my_name, remote_name, domain = '', use_ntlm_v2 = True, sign_options = SIGN_WHEN_REQUIRED, is_direct_tcp = False)
		conn = SMBConnection(username, password, client_name, server_name, use_ntlm_v2 = True, is_direct_tcp = is_direct_tcp)
		smb_authentication_successful = conn.connect(ip, port, timeout = timeout)
		if smb_authentication_successful:
			print "SMB active [null session enabled]: %s:%s" % (ip, port)
			if list_shares:
				list_smb_shares(conn, timeout)
		else:
			# on Windows 7 authentication fails due to disabled null sessions
			print "SMB active [null session disabled]: %s:%s" % (ip, port)
	except:
		if verbose:
			e = sys.exc_info()
			print "%s" % str(e)
	finally:
		if conn:
			conn.close()


def connect_scan(ip, port, timeout, verbose):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((ip, port))
	except socket.timeout as e:
		if verbose:
			print "%s" % e
		return False
	except socket.error as e:
		if verbose:
			print "%s" % e
		return False
	finally:
		s.close()
	return True


def run_scan(ip, port, args):
	list_shares = args.list_shares
	timeout = args.timeout
	verbose = args.verbose
	if verbose:
		print "scanning: %s:%s" % (ip, port)
	connect_successful = connect_scan(ip, port, timeout, verbose)
	if connect_successful:
		if verbose:
			print "port open: %s:%s" % (ip, port)
		smb_scan(ip, port, list_shares, timeout, verbose)


def parse_ports(ip, args):
	if args.port:
		run_scan(ip, args.port, args)
	elif args.portrange:
		port1 = int(args.portrange.split("-")[0])
		port2 = int(args.portrange.split("-")[1])
		for port in range(port1, port2 + 1):
			run_scan(ip, port, args)
	elif args.portfile:
		portfile = open(args.portfile, "r")
		for port in portfile:
			port = port.strip()
			port = int(port)
			run_scan(ip, port, args)
		portfile.close()
	else:
		run_scan(ip, 139, args)
		run_scan(ip, 445, args)


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


def main():
	parser_description = 	"If no ports are specified, ports 139 and 445 are scanned.\n" +\
				"Use -listshares to list shares when enabled null sessions are found."
	parser = argparse.ArgumentParser(description = parser_description, formatter_class=argparse.RawTextHelpFormatter)
	group1 = parser.add_mutually_exclusive_group(required=True)
	group1.add_argument("-hostname", action="store", dest="hostname", help="e.g. example.com")
	group1.add_argument("-ip", action="store", dest="ip", help="e.g. 192.168.0.1")
	group1.add_argument("-ipnetwork", action="store", dest="ipnetwork", help="e.g. 192.168.0.0/24")
	group1.add_argument("-iprange", action="store", dest="iprange", help="e.g. 192.168.0.1-192.168.0.254")
	group1.add_argument("-ipfile", action="store", dest="ipfile", help="e.g. ips.txt")
	group2 = parser.add_mutually_exclusive_group(required=False)
	group2.add_argument("-port", action="store", dest="port", type=int, help="e.g. 139")
	group2.add_argument("-portrange", action="store", dest="portrange", help="e.g. 1-1000")
	group2.add_argument("-portfile", action="store", dest="portfile", help="e.g. ports.txt")
	parser.add_argument("-listshares", action="store_true", dest="list_shares", default=False, required=False, help="list SMB shares")
	parser.add_argument("-timeout", action="store", dest="timeout", type=int, default=5, required=False, help="default 5")
	parser.add_argument("-v", action="store_true", dest="verbose", default=False, required=False)
	args = parser.parse_args()

	parse_ips(args)


if __name__ == '__main__':
	main()
