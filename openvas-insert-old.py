#!/usr/bin/env python3

# Iterate through an openvas output XML file
# and insert relevant information into a Mongo database
# OID is considered the authoritative identifiers of individual
# vulnerabilities, and if a vulnerability or host-vuln mapping
# already exists in Mongo, data provided here will
# be ignored.
#
# v0.2
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

        # First we need to get rid of 'stale' vulnerablity-host mappings.
        # In this case, our logic is: any host that was found in this scan,
        # delete its stale data, because we'll be replacing it.

        # So first let's get a list of hosts found in the scan. It seems the
        # best way of doing this is via the 'ports' section in the report,
        # unintuitively enough.

        if elem.tag == "ports":
            hostlist = [host.text for host in elem.iter('host')]
            hostlist = set(hostlist) # to get unique hosts

            # Delete hostvuln mappings for these hosts.
            for host in hostlist:
                db.hostvuln.remove({'ip': host})


        # Now do this for each 'result' block in the output file
        if elem.tag == "result":
            result = {}

            # this won't go in the result document, but will be used
            # to find the result document we're inserting into or creating
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

            # this will also be reused
            cve = nvtblock.find("cve").text
            result['cve'] = cve
            result['bid'] = nvtblock.find("bid").text
            result['xref'] = nvtblock.find("xref").text

            # the issue is we don't know quite what will be in here for
            # any given vulnerability. So we'll just put them all in the
            # database under the names that OpenVAS gives them
            tags = nvtblock.find("tags").text.split("|")
            for item in tags:
                (tagname, tagvalue) = item.split("=", 1)
                result[tagname] = tagvalue
            result['description'] = elem.find("description").text
            result['threat'] = elem.find("threat").text
            result['updated'] = datetime.datetime.utcnow()
            elem.clear()

            # first, does this vulnerability exist yet in our
            # database? if so, insert it. if not, skip.
            # since not all of them have a CVE or a BID, we will use
            # oid (an OpenVAS identifier) as canonical.

            if db.vulnerabilities.count({'oid': oid}) == 0:
                db.vulnerabilities.insert(result)

            # now we need to see if this vulnerability exists yet for
            # this host. In this case we will update the existing record
            # (to add a new timestamp) if a mapping already exists

            if db.hostvuln.count({'ip': ipaddr, 'oid': oid}) == 0:
                db.hostvuln.insert({'ip': ipaddr,
                                            'oid': oid,
                                            'cve': cve,
                                            'updated': datetime.datetime.utcnow()})
            else:
                db.hostvuln.update_one({'ip': ipaddr,
                                        'oid': oid},
                                        {'$set': {'updated': datetime.datetime.utcnow()}})

            # finally, we need to update our hosts entry for this IP
            # address since it obviously still exists. If it doesn't already
            # exist in our database, that is a shortcoming of our scanning
            # methodology so we need to create a bare-bones record with the
            # information we've collected here.

            if db.hosts.count({'ip': ipaddr}) == 0:
                db.hosts.insert({'ip': ipaddr,
                                    'updated': datetime.datetime.utcnow()})
            else:
                db.hosts.update_one({'ip': ipaddr},
                                    {'$set': {'updated': datetime.datetime.utcnow()}})

    infile.close() # we're done

main()