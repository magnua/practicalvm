#!/usr/bin/env python3

# Iterate through an openvas output XML file
# and insert relevant information into a Mongo database
# OID is considered the authoritative identifiers of individual
# vulnerabilities, and if a vulnerability or host-vuln mapping
# already exists in Mongo, data provided here will
# be ignored.
#
# v0.3
# Andrew Magnusson

from xml.etree.cElementTree import iterparse
from pymongo import MongoClient
import datetime, sys

# globals
# Mongo connection parameters
client = MongoClient('mongodb://localhost:27017')
db = client['vulnmgt']

# host - OIDs map
oidList = {}

# print usage and exit
def usage():
    print ('''
Usage: $ openvas-insert.py <infile>
    ''')

def main():
    if (len(sys.argv) < 2): # no files
        usage()
        exit(0)

# find and open the output XML file
    infile = open(sys.argv[1], 'r')

    # Start parsing the XML tree.
    for event, elem in iterparse(infile):

        # Now do this for each 'result' block in the output file
        if elem.tag == "result":
            result = {}

            # this won't go in the result document, but will be used
            # to find the result document we're inserting into or creating
            # 
            # some 'result' blocks are nested, and we want to ignore those!
            # we can tell if it's one of those because it's missing stuff like
            # the 'host' block
            if (elem.find("host") == None):
                continue
            ipaddr = elem.find("host").text
            (port, proto) = elem.find("port").text.split('/')
            result['port'] = port
            result['proto'] = proto
            nvtblock = elem.find("nvt") # a bunch of stuff is in here

            # this will be reused later
            oid = nvtblock.get("oid")
            result['oid'] = oid
            result['name'] = nvtblock.find("name").text
            result['family'] = nvtblock.find("family").text

            # if it is cvss 0, ignore it.
            cvss = float(nvtblock.find("cvss_base").text)
            if (cvss == 0):
                continue
            result['cvss'] = cvss

            # these fields might contain one or more comma-separated values.
            # result['cve'] = nvtblock.find("cve").text.split(", ")
            result['bid'] = nvtblock.find("bid").text.split(", ")
            result['xref'] = nvtblock.find("xref").text.split(", ")
            
            # Retrieving CVEs from GVM output
            result['cve'] = []
            try:
                refs = nvtblock.find("refs").findall("ref")
                for ref in refs:
                    if ref.get('type') == "cve":
                        result['cve'].append(ref.get('id'))
            except:
                pass

            # the issue is we don't know quite what will be in here for
            # any given vulnerability. So we'll just put them all in the
            # database under the names that OpenVAS gives them
            tags = nvtblock.find("tags").text.split("|")
            for item in tags:
                (tagname, tagvalue) = item.split("=", 1)
                result[tagname] = tagvalue
            result['threat'] = elem.find("threat").text
            result['updated'] = datetime.datetime.utcnow()
            elem.clear()

            # first, does this vulnerability exist yet in our
            # database? if so, insert it. if not, skip.
            # since not all of them have a CVE or a BID, we will use
            # oid (an OpenVAS identifier) as canonical.

            if db.vulnerabilities.count({'oid': oid}) == 0:
                db.vulnerabilities.insert(result)

            # Here we're adding the OID to the dictionary of host-oid lists
            # specified above. At the end of this main loop we'll go through
            # each key (aka each IP) and add its list of OIDs to the Mongo
            # document.

            # Initialize the dictionary key if it's not yet there
            if ipaddr not in oidList.keys():
                oidList[ipaddr] = []
            oidList[ipaddr].append({'proto': proto, 'port': port, 'oid': oid})


        # Now, we'll add the OID information to each host. This will provide
        # the link between hosts and vulnerabilities. If the host doesn't
        # exist in our database, that is a shortcoming of our scanning
        # methodology so we need to create a bare-bones record with the
        # information we've collected here.

        for ipaddress in oidList.keys():
            if db.hosts.count({'ip': ipaddress}) == 0:
                db.hosts.insert({'ip': ipaddress,
                                    'mac': { 'addr': "", 'vendor': "Unknown" },
                                    'ports': [],
                                    'hostnames': [],
                                    'os': [],
                                    'updated': datetime.datetime.utcnow(),
                                    'oids': oidList[ipaddress]})
            else:
                db.hosts.update_one({'ip': ipaddress},
                                    {'$set': {  'updated': datetime.datetime.utcnow(),
                                        'oids': oidList[ipaddress]}})

    infile.close() # we're done

main()
