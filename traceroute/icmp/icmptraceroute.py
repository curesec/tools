#!/usr/bin/env python2
#copyright 2014 curesec gmbh, ping@curesec.com

import array
import random
import sys
import struct
import socket
import time


def main():
	if len(sys.argv) < 2:
		usage()
		sys.exit(1)

	target = sys.argv[1]
	n = False
	timeout = 3
	maxhops = 30

	if len(sys.argv) >= 3:
		if sys.argv[2].lower() == "true":
			n = True
	if len(sys.argv) >= 4:
		timeout = int(sys.argv[3])
	if len(sys.argv) >= 5:
		maxhops = int(sys.argv[4])

	icmptraceroute(target, n, timeout, maxhops)


def usage():
	print "usage: %s target [n [timeout [maxhops]]]" % sys.argv[0]
	print "default:\tn: False"
	print "\t\ttimeout: 3"
	print "\t\tmaxhops: 30"
	print "examples:\t%s google.com" % sys.argv[0]
	print "\t\t%s 8.8.8.8 True 5 20" % sys.argv[0]




# http://stackoverflow.com/questions/1767910/checksum-udp-calculation-python

if struct.pack("H",1) == "\x00\x01": # big endian
	def checksum(pkt):
		if len(pkt) % 2 == 1:
			pkt += "\0"
		s = sum(array.array("H", pkt))
		s = (s >> 16) + (s & 0xffff)
		s += s >> 16
		s = ~s
		return s & 0xffff
else:
	def checksum(pkt):
		if len(pkt) % 2 == 1:
			pkt += "\0"
		s = sum(array.array("H", pkt))
		s = (s >> 16) + (s & 0xffff)
		s += s >> 16
		s = ~s
		return (((s>>8)&0xff)|s<<8) & 0xffff



def icmptraceroute(target, n, timeout, maxhops):
	# ICMP identifier is two bytes long, make it random
	IDENTIFIER = random.randint(0, 65535)

	try:
		ip_target = socket.gethostbyname(target)
	except socket.error as e:
		print "Socket error: %s" % e
		sys.exit(1)

	print "traceroute (%s) to %s (%s), %d hops max" % ("ICMP", target, ip_target, maxhops)

	for ttl in range(1, maxhops):
		# s1 is the sender, s2 is the receiver
		s1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		s1.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
		s1.settimeout(timeout)

		s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		s2.settimeout(timeout)
		s2.bind(("0.0.0.0", 0))

		icmp_type = 8
		icmp_code = 0
		icmp_checksum = 0
		icmp_identifier = IDENTIFIER
		# use ttl as sequence number as it is unique for every packet sent
		icmp_sequence = ttl

		icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)
		icmp_checksum = checksum(icmp_header)
		icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)

		try:
			s1.connect((ip_target, 0))
			s1.send(icmp_header)
		except socket.error as e:
			# can that even happen?
			print "Socket error: %s" % e
			s1.close()
			s2.close()
			sys.exit(1)

		# count unexpectedly received ICMP packets
		# break when more than 10 are received without receiving an ICMP echo reply or an ICMP TTL exceeded
		i = 0
		ip_hop = ""
		while True:
			try:
				data, addr = s2.recvfrom(1024)
				ip_hop  = addr[0]
			except socket.error as e:
				# probably a timeout which is not unlikely to happen
				output(ttl)
				break

			# debug
			#print "Packet from %r: %r" % (addr,data)

			ip_header = data[0:20]
			ip_version_length = struct.unpack("!B", ip_header[0:1])[0]
			ip_version = ip_version_length >> 4
			ip_length = ip_version_length & 0xF
			ip_length = ip_length * 4

			# if not IPv4
			if ip_version != 4:
				continue

			icmp_header = data[ip_length:]
			# just to be sure, icmp header should not be longer than 8 bytes
			icmp_header = icmp_header[0:8]

			icmp_headers = struct.unpack("!BBHHH", icmp_header)
			icmp_type = icmp_headers[0]
			icmp_code = icmp_headers[1]
			icmp_checksum = icmp_headers[2]
			icmp_identifier = icmp_headers[3]
			icmp_sequence = icmp_headers[4]

			if (icmp_type == 0 and icmp_code == 0 and icmp_identifier == IDENTIFIER and icmp_sequence == ttl) or (icmp_type ==  11 and icmp_code == 0):
				output(ttl, ip_hop, n)
				break
			else:
				# received some other ICMP packet
				i = i + 1
				if i >= 10:
					output(ttl)
					break

		s1.close()
		s2.close()
		if ip_target == ip_hop:
			break


def output(ttl, ip = "", n = False):
	if ip:
		if n:
			reversename = getreversename(ip)
		else:
			reversename = ip
		print "%d: %s (%s)" % (ttl, reversename, ip)
	else:
		print "%d: ***" % (ttl)

def getreversename(ip):
	try:
		name, alias, addresslist = socket.gethostbyaddr(ip)
		return name
	except:
		return ip

if __name__ == "__main__":
	main()
