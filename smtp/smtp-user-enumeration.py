#!/usr/bin/env python2
#copyright curesec gmbh 2014, ping@curesec.com

import argparse
import socket
import sys

class SMTPUserEnumerator(object):
   def __init__(self, rhost, rport, command, userfile, timeout, verbose):
      self.rhost = rhost
      self.rport = int(rport)
      self.command = command
      self.userfile = userfile
      self.timeout = int(timeout)
      self.verbose = verbose
      self.hits = []


   def createsocket(self):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(self.timeout)
      s.connect((self.rhost, self.rport))
      return s

   def testconnection(self):
      if self.verbose:
         print("Testing connection...")      
      s = None
      try:
         s = self.createsocket()
      except socket.error as e:
         print("socket.error: " + str(e))
         return False
      finally:
         if s:
            s.close()
      return True

   def run(self):
      print("Starting user enumeration with command " + self.command + "...")
      f = open(self.userfile, "r")
      for username in f.readlines():
         username = username.strip()
         self.testusername(username)


   def testusername(self, username):
      if self.verbose:
         print("Testing username " + username + " with command " + self.command + "...")
      s = None
      log = ""
      reply = ""
      try:
         s = self.createsocket()

         # grab banner
         data = s.recv(1024)
         log = log + data

         s.send("HELO a\r\n")
         data = s.recv(1024)
         log = log + data

         if self.command == "VRFY":
            s.send("VRFY " + username + "\r\n")
         elif self.command == "EXPN":
            s.send("EXPN " + username + "\r\n")
         else: #RCPT
            s.send("MAIL FROM:example@mail.com\r\n")
            data = s.recv(1024)
            log = log + data
            s.send("RCPT TO:" + username + "\r\n")
         data = s.recv(1024)
         log = log + data
         reply = data
      except socket.error as e:
         print("socket.error: " + str(e))
      finally:
         if s:
            s.close()

      if reply.startswith("2"):
         if not username in self.hits:
            self.hits.append(username)

      if self.verbose:
         print("Received output:\n" + log)


   def printhits(self):
      print(str(len(self.hits)) + " valid usernames found")
      for username in self.hits:
         print("[" + username + "]")



def checkiffileexists(path):
   try:
      open(path, "r")
   except IOError:
      print("Unable to open " + path)
      exit(1)


def main(argv):
   description = "### SMTP user enumeration ###\n" + \
                 "It is based on the SMTP commands: VRFY, EXPN, RCPT.\n" + \
                 "Results may be inaccurate (false positives) as not all SMTP servers act the same.\n" +\
                 "Furthermore, this script does not support StartTLS or authentication.\n" +\
                 "To inspect the server's resonse, use the -v verbosity switch.\n" +\
                 "Output of valid usernames are in the form of: [username]\n\n" +\
                 "example:\n" +\
                 "smtp-user-enumeration.py -rhost 192.168.10.10 -command VRFY -userfile users.txt"

   parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
   parser.add_argument("-rhost", action="store", dest="rhost", required=True, help="host name or IP address")
   parser.add_argument("-rport", action="store", dest="rport", required=False, default="25", help="default: 25")
   parser.add_argument("-command", action="store", dest="command", required=True, help="choose VRFY, EXPN, RCPT or ALL")
   parser.add_argument('-userfile', action="store", dest="userfile", required=True, help="file containing usernames separated by newlines")
   parser.add_argument("-timeout", action="store", dest="timeout", default="5", required=False, help="in seconds. Default: 5")
   parser.add_argument("-v", action="store_true", dest="verbose", required=False, help="verbose")

   args = parser.parse_args()

   if args.command != "VRFY" and args.command != "EXPN" and args.command != "RCPT" and args.command != "ALL":
      print("command must either be 'VRFY', 'EXPN', 'RCPT' or 'ALL'")
      sys.exit(1)

   checkiffileexists(args.userfile)

   smtpuserenumerator = SMTPUserEnumerator(args.rhost, args.rport, args.command, args.userfile, args.timeout, args.verbose)
   isconnected = smtpuserenumerator.testconnection()
   if isconnected:
      if smtpuserenumerator.command == "ALL":
         smtpuserenumerator.command = "VRFY"
         smtpuserenumerator.run()
         smtpuserenumerator.command = "EXPN"
         smtpuserenumerator.run()
         smtpuserenumerator.command = "RCPT"
         smtpuserenumerator.run()
      else:
         smtpuserenumerator.run()
      smtpuserenumerator.printhits()
   else:
      print("Unable to connect to " + smtpuserenumerator.rhost + ":" + str(smtpuserenumerator.rport))


main(sys.argv[1:])
