#!/usr/bin/env python2
#copyright 2014 curesec gmbh, ping@curesec.com

# Download databases from:
# http://dev.maxmind.com/geoip/geoip2/geolite2/
# http://geolite.maxmind.com/download/geoip/database/GeoLite2-City-CSV.zip
# http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country-CSV.zip

# Examples:
# ./geoip-v02.py -ipcountry 87.162.33.167
# ./geoip-v02.py -ipcity 87.162.33.167
# ./geoip-v02.py -city Berlin"
# ./geoip-v02.py -city "New York"
# ./geoip-v02.py -country Germany

import argparse
from netaddr import IPNetwork, IPAddress
import sys



class GeoIP(object):
   countryblockfile = "/usr/share/geoip/GeoLite2-Country-Blocks.csv"
   countrylocationfile = "/usr/share/geoip/GeoLite2-Country-Locations.csv"
   cityblockfile = "/usr/share/geoip/GeoLite2-City-Blocks.csv"
   citylocationfile = "/usr/share/geoip/GeoLite2-City-Locations.csv"


   @staticmethod
   def iptoname(ip, blockfile, locationfile):
      # network_start_ip,network_mask_length,geoname_id,...
      headerline = GeoIP.getheaderline(blockfile)
      blockline = GeoIP.getlinefromip(ip, blockfile)
      if not blockline:
         print("Error: IP address not found")
         return
      splits1 = headerline.split(",")
      splits2 = blockline.split(",")
      print(splits1[2] + ": " + splits2[2])
      print(splits1[3] + ": " + splits2[3])
      print(splits1[4] + ": " + splits2[4])
      print(splits1[5] + ": " + splits2[5])
      print(splits1[6] + ": " + splits2[6])
      print(splits1[7] + ": " + splits2[7])
      print(splits1[8] + ": " + splits2[8])
      print(splits1[9] + ": " + splits2[9])
      # geoname_id,continent_code,continent_name,country_iso_code,country_name,...
      headerline = GeoIP.getheaderline(locationfile)
      locationline = GeoIP.getinfofromid(splits2[2], locationfile)
      splits1 = headerline.split(",")
      splits2 = locationline.split(",")
      print("")
      print(splits1[0] + ": " + splits2[0])
      print(splits1[1] + ": " + splits2[1])
      print(splits1[2] + ": " + splits2[2])
      print(splits1[3] + ": " + splits2[3])
      print(splits1[4] + ": " + splits2[4])
      print(splits1[5] + ": " + splits2[5])
      print(splits1[6] + ": " + splits2[6])
      print(splits1[7] + ": " + splits2[7])
      print(splits1[8] + ": " + splits2[8])
      print(splits1[9] + ": " + splits2[9])
            
   @staticmethod
   def getlinefromip(ip, blockfile):
      f = open(blockfile, "r")
      # skip header line
      f.readline()      
      for line in f:
         # a line looks like this:
         # ::ffff:1.0.128.0,113,1605651,1605651,,,,,0,0
         startip = line.split(",")[0].split(":")[-1]
         # some lines contain ip6 but not ip4 addresses
         if not startip:
            continue
         # I don't understand the logic behind subtracting 96 but it works
         netrange = int(line.split(",")[1]) - 96
         # http://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python
         if IPAddress(ip) in IPNetwork(startip + "/" + str(netrange)):
            print("range: " + startip + "/" + str(netrange))
            f.close()
            return line.strip()
      f.close()
      return ""

   @staticmethod
   def getinfofromid(id, locationfile):
      f = open(locationfile, "r")
      headerline = f.readline()
      for line in f:
         # a line looks like this:
         # 2921044,EU,Europe,DE,Germany,,,,,
         if line.startswith(id + ","):
            f.close()
            return line.strip()
      f.close()
      return ""

   @staticmethod
   def getheaderline(path):
      f = open(path, "r")
      line = f.readline().strip()
      f.close()
      return line





   @staticmethod
   # mytype is either "country" or "city"
   def nametoip(mytype, name, blockfile, locationfile):
      myid = GeoIP.getidfromname(mytype, name, locationfile)
      if not myid:
         if mytype == "country":
            print("Error: County not found")
         else:
            print("Error: City not found")
         return
      GeoIP.getrangesfromid(myid, blockfile)

   @staticmethod
   def getidfromname(mytype, name, locationfile):
      f = open(locationfile, "r")
      # skip header line
      headerline = f.readline()
      for line in f:
         line = line.strip()
         splits = line.split(",")
         if mytype == "country":
            if len(splits) < 5:
               continue
            # some names are saved with double quotes
            # 2921044,EU,Europe,DE,Germany,,,,,
            # 6252001,NA,"North America",US,"United States",,,,,
            if splits[4] == name or splits[4] == "\"" + name + "\"":
               f.close()
               return splits[0]
         else:
            # city names containing space characters are saved with underscore characters
            # 4776222,NA,"North America",US,"United States",VA,Virginia,Norfolk,544,America/New_York
            name = name.replace(" ", "_")
            if splits[-1].endswith("/" + name):
               f.close()
               return splits[0]
      f.close()
      return ""

   @staticmethod
   def getrangesfromid(myid, blockfile):
      f = open(blockfile, "r")
      # skip header line
      f.readline()      
      for line in f:
         # a line looks like this:
         # ::ffff:1.0.128.0,113,1605651,1605651,,,,,0,0
         splits = line.split(",")
         geoid = splits[2]
         if geoid == myid:
            startip = splits[0].split(":")[-1]
            # some lines do not contain ip4 addresses
            if not startip:
               continue
            # I don't understand the logic behind subtracting 96
            netrange = int(splits[1]) - 96
            print(startip + "/" + str(netrange))
      f.close()





   @staticmethod
   def checkiffileexists(path):
      try:
         open(path, "r")
      except IOError:
         print("Unable to open " + path)
         exit(1)





def main(argv):
   GeoIP.checkiffileexists(GeoIP.countryblockfile)
   GeoIP.checkiffileexists(GeoIP.countrylocationfile)
   GeoIP.checkiffileexists(GeoIP.cityblockfile)
   GeoIP.checkiffileexists(GeoIP.citylocationfile)
   
   parser = argparse.ArgumentParser()
   
   group = parser.add_mutually_exclusive_group(required="True")
   group.add_argument('-ipcountry', dest='ipcountry')
   group.add_argument('-ipcity', dest='ipcity')
   group.add_argument('-country', dest='country')
   group.add_argument('-city', dest='city')

   args = parser.parse_args()

   if args.ipcountry:
      GeoIP.iptoname(args.ipcountry, GeoIP.countryblockfile, GeoIP.countrylocationfile)
   elif args.ipcity:
      GeoIP.iptoname(args.ipcity, GeoIP.cityblockfile, GeoIP.citylocationfile)
   elif args.country:
      GeoIP.nametoip("country", args.country, GeoIP.countryblockfile, GeoIP.countrylocationfile)
   else:
      GeoIP.nametoip("city", args.city, GeoIP.cityblockfile, GeoIP.citylocationfile)


if __name__ == '__main__':
   main(sys.argv[1:])
