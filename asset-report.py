#!/usr/bin/env python3

# Simple asset report script
# Runs against all assets in the Mongo database
# Output is in CSV format
# v0.1
# Andrew Magnusson

from pymongo import MongoClient
import datetime, sys, csv

# globals
# Mongo connection parameters
client = MongoClient('mongodb://localhost:27017')
db = client['vulnmgt']

# Output filename
outputFile = "asset-report.csv"

# CSV column header
header = ['IP Address', 'Hostname', 'OS', 'Open TCP Ports', 'Open UDP Ports', 'Detected Services', 'Vulnerabilities Found', 'List of CVEs']

# print usage and exit
def usage():
    print ('''
Usage: $ asset-report.py

    ''')

def main():

    # open CSV
    with open(outputFile, 'w') as csvfile:
        linewriter = csv.writer(csvfile)
    # print header
        linewriter.writerow(header)
    # get list of assets
        iplist = db.hosts.distinct("ip")
    # for each asset...
        for ip in iplist:
    # grab relevant asset information
            details = db.hosts.find_one({'ip':ip})
    # construct open ports and services fields
            openTCPPorts = ""
            openUDPPorts = ""
            detectedServices = ""
            serviceList = []
            for portService in details['ports']:
                if portService['proto'] == "tcp":
                    openTCPPorts += portService['port'] + "; "
                elif portService['proto'] == "udp":
                    openUDPPorts += portService['port'] + "; "
                serviceList.append(portService['service'])

            # deduplicate service names and write to a string
            serviceList = set(serviceList)
            for service in serviceList:
                detectedServices += service + "; "

    # make string of vulns found, resolving them into CVE IDs (if they exist, otherwise NOCVE)
            cveList = ""
            if 'oids' in details.keys():
                vulnCount = len(details['oids'])
                for oidItem in details['oids']:
                    cveList += db.vulnerabilities.find_one({'oid': oidItem['oid']}, {'cve':1})['cve'] + "; "
            else:
                vulnCount = 0


    # in case there is no OS field
            if details['os'] != []:
                os = details['os'][0]['osname']
            else:
                os = "Unknown"

    # assemble record into a line of CSV
            record = [ details['ip'], details['hostname'], os, openTCPPorts, openUDPPorts, detectedServices, vulnCount, cveList]
    # print assembled CSV line to output file
            linewriter.writerow(record)

    # close CSV
    csvfile.close()

main()
