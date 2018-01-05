#!/usr/bin/env python3

# Iterate through an nmap output XML file
# and insert relevant information into a Mongo database
# IP addresses are considered authoritative identifiers of individual
# hosts, and if a host already exists in Mongo, data provided here will
# overwrite older data in the existing Mongo document.
#
# v0.5
# Andrew Magnusson

from xml.etree.cElementTree import iterparse
from pymongo import MongoClient
import datetime, sys

# globals
# Mongo connection parameters
client = MongoClient('mongodb://localhost:27017')
db = client['vulnmgt']

# print usage and exit
def usage():
    print ('''
Usage: $ nmap-insert.py <infile>
    ''')
def main():
    if (len(sys.argv) < 2): # no files
        usage()
        exit(0)

# find and open the output XML file
    infile = open(sys.argv[1], 'r')
    #xmlfile = infile.read()

# Do this for each 'host' block in the output file
    for event, elem in iterparse(infile):
        if elem.tag == "host":
            # add some defaults in case these come up empty
            macaddr = {'addr': "", 'vendor': "Unknown"}
            hostnames = []
            os = []

            # addresses
            addrs = elem.findall("address")
            # all addresses, IPv4, v6 (if exists), MAC
            for addr in addrs:
                type = addr.get("addrtype")
                if (type == "ipv4"):
                    ipaddr = addr.get("addr")
                if (type == "mac"): # there are two useful things we can get here
                    macaddr = {"addr": addr.get("addr"),
                                "vendor": addr.get("vendor")}

            # hostname(s) (and types)
            hostlist = elem.findall("hostname")
            for host in hostlist:
                hostnames += [{"name": host.get("name"),
                                "type": host.get("type")}]

            # OS detection
            # We will be conservative and put it all in there.
            oslist = elem.find("os").findall("osmatch")
            for oseach in oslist:
                cpelist = []
                for cpe in oseach.findall("osclass"):
                    cpelist += {cpe.findtext("cpe")}
                os += [{"osname": oseach.get("name"),
                        "accuracy": oseach.get("accuracy"),
                        "cpe": cpelist}]

            # ports
            portlist = elem.find("ports").findall("port")
            ports = []
            for port in portlist:
                ports += [{"proto": port.get("protocol"),
                        "port": port.get("portid"),
                        "state": port.find("state").get("state"),
                        "service": port.find("service").get("name")
                            }]
            elem.clear()

            # generate the document for insertion into Mongo
            host = {"ip": ipaddr,
                    "hostnames": hostnames,
                    "mac": macaddr,
                    "ports": ports,
                    "os": os,
                    "updated": datetime.datetime.utcnow()
                    }

            # check if this host exists already
            # update if so, insert if not.
            if db.hosts.count({'ip': ipaddr}) > 0:
                db.hosts.update_one(
                        {"ip": ipaddr},
                        {"$set": host}
                        )
            else:
                db.hosts.insert(host)




    infile.close() # we're done

main()
