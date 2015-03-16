#!/usr/bin/env python2
#copyright 2014 curesec gmbh, ping@curesec.com


import argparse
import netaddr
import socket
import sys

import smb.base
from smb.SMBConnection import SMBConnection


# https://pythonhosted.org/pysmb/api/smb_SMBConnection.html


# https://pythonhosted.org/pysmb/api/smb_SharedDevice.html
def smb_list_shares(conn, timeout):
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


def smb_list_snapshots(conn, share, remotepath, timeout):
	for snapshot in conn.listSnapshots(share, remotepath, timeout):
		# printing snapshots was not tested yet
		print "%s" % snapshot

# https://pythonhosted.org/pysmb/api/smb_SharedFile.html
def smb_list_path(conn, share, remotepath, timeout, verbose):
	for shared_file in conn.listPath(share, remotepath, timeout = timeout):
		if shared_file.isDirectory:
			print "dir:  %s" % shared_file.filename
		else:
			print "file: %s   [%d]" % (shared_file.filename, shared_file.file_size)


# https://pythonhosted.org/pysmb/api/smb_SharedFile.html
def smb_get_attributes(conn, share, remotepath, timeout, verbose):
	shared_file = conn.getAttributes(share, remotepath, timeout = timeout)
	shared_file_alloc_size = shared_file.alloc_size
	shared_file_create_time = shared_file.create_time
	shared_file_file_attributes = shared_file.file_attributes
	shared_file_file_size = shared_file.file_size
	shared_file_filename = shared_file.filename
	shared_file_isDirectory = shared_file.isDirectory
	shared_file_isReadOnly = shared_file.isReadOnly
	shared_file_last_access_time = shared_file.last_access_time
	shared_file_last_attr_change_time = shared_file.last_attr_change_time
	shared_file_last_write_time = shared_file.last_write_time
	shared_file_short_name = shared_file.short_name
	print "alloc_size:            %s bytes" % shared_file_alloc_size
	print "create_time:           %s" % shared_file_create_time
	print "file_attributes:       %s" % shared_file_file_attributes
	print "file_size:             %s bytes" % shared_file_file_size
	print "filename:              %s" % shared_file_filename
	print "isDirectory:           %s" % shared_file_isDirectory
	print "isReadOnly:            %s" % shared_file_isReadOnly
	print "last_access_time:      %s" % shared_file_last_access_time
	print "last_attr_change_time: %s" % shared_file_last_attr_change_time
	print "last_write_time:       %s" % shared_file_last_write_time
	print "short_name:            %s" % shared_file_short_name


def smb_retrieve_file(conn, share, remotepath, localpath, timeout):
	localfile = open(localpath, "w")
	conn.retrieveFile(share, remotepath, localfile, timeout)
	print "file download complete"

# very important:
# offset and maxlength must be integers
def smb_retrieve_file_from_offset(conn, share, remotepath, localpath, offset, maxlength, timeout):
	localfile = open(localpath, "w")
	conn.retrieveFileFromOffset(share, remotepath, localfile, offset, maxlength, timeout)
	print "file download complete"

def smb_store_file(conn, share, localpath, remotepath, timeout):
	localfile = open(localpath, "r")
	conn.storeFile(share, remotepath, localfile, timeout)
	print "file upload complete"

def smb_rename_file(conn, share, oldpath, newpath, timeout):
	conn.rename(share, oldpath, newpath, timeout)
	print "file/directory renamed"

def smb_delete_file(conn, share, remotepath, timeout):
	conn.deleteFiles(share, remotepath, timeout)
	print "file deleted"

def smb_delete_directory(conn, share, remotepath, timeout):
	conn.deleteDirectory(share, remotepath, timeout)
	print "directory deleted"



def smb_connect(args):
	ip = args.ip
	port = args.port
	username = args.username
	password = args.password
	domain = args.domain
	timeout = args.timeout
	verbose = args.verbose

	client_name = "client"
	server_name = ip
	if port == 445:
		is_direct_tcp = True
	else:
		is_direct_tcp = False

	# def __init__(self, username, password, my_name, remote_name, domain = '', use_ntlm_v2 = True, sign_options = SIGN_WHEN_REQUIRED, is_direct_tcp = False)
	conn = SMBConnection(username, password, client_name, server_name, domain = domain, use_ntlm_v2 = True, is_direct_tcp = is_direct_tcp)
	smb_authentication_successful = conn.connect(ip, port, timeout = timeout)
	if smb_authentication_successful:
		print "authentication successful"
		return conn
	else:
		print "authentication failed"
		return None

def smb_close(conn):
	conn.close()



def run_smb_action(args):
	timeout = args.timeout
	verbose = args.verbose
	try:
		conn = smb_connect(args)
		if conn:
			if args.listshares:
				smb_list_shares(conn, timeout)
			elif args.listsnapshots:
				smb_list_snapshots(conn, args.listsnapshots[0], args.listsnapshots[1], timeout)
			elif args.listpath:
				smb_list_path(conn, args.listpath[0], args.listpath[1], timeout, verbose)
			elif args.getattributes:
				smb_get_attributes(conn, args.getattributes[0], args.getattributes[1], timeout, verbose)
			elif args.retrievefile:
				smb_retrieve_file(conn, args.retrievefile[0], args.retrievefile[1], args.retrievefile[2], timeout)
			elif args.retrievefilefromoffset:
				smb_retrieve_file_from_offset(conn, args.retrievefilefromoffset[0], args.retrievefilefromoffset[1], args.retrievefilefromoffset[2], int(args.retrievefilefromoffset[3]), int(args.retrievefilefromoffset[4]), timeout)
			elif args.storefile:
				smb_store_file(conn, args.storefile[0], args.storefile[1], args.storefile[2], timeout)
			elif args.rename:
				smb_rename_file(conn, args.rename[0], args.rename[1], args.rename[2], timeout)
			elif args.delete:
				smb_delete_file(conn, args.delete[0], args.delete[1], timeout)
			elif args.deletedirectory:
				smb_delete_directory(conn, args.deletedirectory[0], args.deletedirectory[1], timeout)
			smb_close(conn)	
	except Exception as e:
		if args.verbose:
			print "something went wrong"
			print "%s" % e
		else:
			print "something went wrong. use -v for more details"



def main():
	parser_description =	"-listsnapshots is only supported on Windows Vista and Windows 7.\n" +\
        	 		"When using -retrievefilefromoffset, set maxlength to -1 to read until EOF.\n" +\
        	 		"When testing, -rename worked only on Windows systems."
        parser = argparse.ArgumentParser(description = parser_description, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-ip", action="store", dest="ip", required=True, help="e.g. 192.168.0.1")
	parser.add_argument("-port", action="store", dest="port", required=True, type=int, help="e.g. 139")
	parser.add_argument("-username", action="store", dest="username", required=True, help="e.g. administrator")
	parser.add_argument("-password", action="store", dest="password", required=True, help="e.g. secret")
	parser.add_argument("-domain", action="store", dest="domain", default="", required=False, help="e.g. WORKGROUP")

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-listshares", action="store_true", dest="listshares")
	group.add_argument("-listsnapshots", action="store", dest="listsnapshots", nargs=2, metavar=("share", "remotepath"))
	group.add_argument("-listpath", action="store", dest="listpath", nargs=2, metavar=("share", "remotepath"))
	group.add_argument("-getattributes", action="store", dest="getattributes", nargs=2, metavar=("share", "remotepath"))
	group.add_argument("-retrievefile", action="store", dest="retrievefile", nargs=3, metavar=("share", "remotepath", "localpath"))
	group.add_argument("-retrievefilefromoffset", action="store", dest="retrievefilefromoffset", nargs=5, metavar=("share", "remotepath", "localpath", "offset", "maxlength"))
	group.add_argument("-storefile", action="store", dest="storefile", nargs=3, metavar=("share", "localpath", "remotepath"))
	group.add_argument("-rename", action="store", dest="rename", nargs=3, metavar=("share", "oldpath", "newpath"))
	group.add_argument("-delete", action="store", dest="delete", nargs=2, metavar=("share", "remotepath"))
	group.add_argument("-deletedirectory", action="store", dest="deletedirectory", nargs=2, metavar=("share", "remotepath"))

	parser.add_argument("-timeout", action="store", dest="timeout", type=int, default=5, required=False, help="default 5")
	parser.add_argument("-v", action="store_true", dest="verbose", default=False, required=False)
	args = parser.parse_args()

	run_smb_action(args)


if __name__ == '__main__':
	main()
