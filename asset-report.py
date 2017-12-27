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
outputFile = asset-report.csv

# CSV column header
header = ['IP Address', 'Hostname', 'OS', 'Open TCP Ports', 'Open UDP Ports', 'Detected Services', 'Vulnerabilities Found', 'List of Vulnerabilities']

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
            details = db.hosts.find({'ip':ip})
    # construct open ports and services fields
            openTCPPorts = ""
            openUDPPorts = ""
            detectedServices = ""
            serviceList = []
            for portService in details.ports:
                if portService.proto == "TCP":
                    openTCPPorts += portService.port + "; "
                elif portService.proto == "UDP":
                    openUDPPorts += portService.port + "; "
                serviceList.push(portService.service)

            # deduplicate service names and write to a string
            serviceList = set(serviceList)
            for service in serviceList:
                detectedServices += service + "; "

    # get list of vulnerability IDs (by CVE)
            cves = db.hostvuln.find({'ip':ip})

    # count CVEs
            cveCount = cves.length()

    # assemble record into a line of CSV
            record = [ details.ip, details.hostname, details.os.osname, openTCPPorts, openUDPPorts, detectedServices, cveCount, cves]
    # print assembled CSV line to output file
            linewriter.writerow(record)

    # close CSV
    close(outputFile)

main()
