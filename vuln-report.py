#!/usr/bin/env python3

# Simple vulnerability report script
# Runs against all known vulnerabilities in the Mongo database
# Output is in CSV format
# v0.1
# Andrew Magnusson

from pymongo import MongoClient
import datetime, sys, csv

# globals
# Mongo connection parameters
client = MongoClient('mongodb://localhost:27017')
db = client['vulnmgt']
cvedb = client['cvedb']

# Output filename
outputFile = "vuln-report.csv"

# CSV column header
header = ['CVE ID', 'Description', 'CVSS', 'Confidentiality Impact', 'Integrity Impact', 'Availability Impact', 'Access Vector', 'Access Complexity', 'Authentication Required', 'Hosts Affected', 'List of Hosts']

# print usage and exit
def usage():
    print ('''
Usage: $ vuln-report.py

    ''')

def main():

    # open CSV
    with open(outputFile, 'w') as csvfile:
        linewriter = csv.writer(csvfile)
    # print header
        linewriter.writerow(header)
    # initialize the host to CVE map object
        hostCveMap = {}
    # get list of assets with OIDs associated
        hostList = db.hosts.find({'oids': {'$exists' : 'true'}})
    # for each asset...
        for host in hostList:
    # make string of vulns found, resolving them into CVE IDs (if they exist, otherwise NOCVE)
            ip = host['ip']

            for oidItem in host['oids']:
                cveList = db.vulnerabilities.find_one({'oid': oidItem['oid']})['cve']
    # because this is a list of one or more items:
                for cve in cveList:

    # skip the NOCVE type, since it's not really useful to us
                    if cve == "NOCVE":
                        continue

    # if there are already IPs mapped to this vulnerability
                    if cve in hostCveMap.keys():
    # ignore duplicates
                        if ip not in hostCveMap[cve]:
                            hostCveMap[cve].append(ip)
    # if there aren't any IPs yet, create a new list with this as the first item
                    else:
                        hostCveMap[cve] = [ ip ]

    # now, for each CVE that we've found...
        for cve in hostCveMap.keys():

    # look up CVE details in cve-search database
            cvedetails = cvedb.cves.find_one({'id': cve})

    # get affected host information
            affectedHosts = len(hostCveMap[cve])
            listOfHosts = ""
            for host in hostCveMap[cve]:
                listOfHosts += host + "; "

    # assemble record into a line of CSV
            record = [ cve, "", cvedetails['summary'], cvedetails['cvss'],
                    cvedetails['impact']['confidentiality'], cvedetails['impact']['integrity'],
                    cvedetails['impact']['availability'], cvedetails['access']['vector'],
                    cvedetails['access']['complexity'], cvedetails['access']['authentication'],
                    affectedHosts, listOfHosts]
    # print assembled CSV line to output file
            linewriter.writerow(record)

    # close CSV
    csvfile.close()

main()
