#!/usr/bin/env python3

# Detailed asset report
# Runs against a customizable IP address range or 0.0.0.0
# Output is in HTML format
# v0.1
# Andrew Magnusson

from pymongo import MongoClient
from operator import itemgetter
import datetime, sys, ipaddress
from yattag import Doc

# globals
# Mongo connection parameters
client = MongoClient('mongodb://localhost:27017')
db = client['vulnmgt']

# Output filename
outputFile = "detailed-asset-report.html"


# print usage and exit
def usage():
    print ('''
Usage: $ detailed-assets.py <IP range in CIDR, optional>

    ''')

def main():

    # check if there's a network. If not, use 0.0.0.0
    if len(sys.argv) > 1:
        network = sys.argv[1]
    else:
        network = '0.0.0.0/0'
    networkObj = ipaddress.ip_network(network)
    print(networkObj)

    # create HTML document object (will write to file at the end of the script)
    doc, tag, text, line = Doc().ttl()

    with tag('html'):
        with tag('head'):
            line('title', 'Asset report for ' + network)
        with tag('body'):
            line('h1', 'Asset report for ' + network)

    # get list of assets and sort
    # (since this won't be a sortable CSV!)
    # the sort key here is leveraging the
    # ipaddress library to do proper sorts.
            iplist = db.hosts.distinct("ip")
            iplist.sort(key=ipaddress.ip_address)
    # for each asset...
            for ip in iplist:
    # first check if the IP is in the configured range. If not, go to the next
                if ipaddress.ip_address(ip) not in networkObj:
                    continue
    # grab relevant asset information
                details = db.hosts.find_one({'ip':ip})

    # output basic host information in a nicely
    # formatted fashion.

    # check if there are detected OS fields; if so, choose the one with the
    # highest confidence.
                osList = details['os']
                if osList != []:
                    osList.sort(key=itemgetter('accuracy'))
                    os = osList[0]['osname']
                    cpe = osList[0]['cpe'][0]
                else:
                    os = "Unknown"
                    cpe = "None"
                line('h2', ip)
                line('b', 'Detected OS: ')
                text(os + " (" + str(cpe) + ")")
                doc.stag('br')
                line('b', 'MAC address: ')
                text("{} ({})".format(details['mac']['addr'], details['mac']['vendor']))

    # construct open ports and services matrices (TCP and UDP)
    # and sort them for display
                openTCPPorts = []
                openUDPPorts = []
                for portService in details['ports']:
                    if portService['proto'] == "tcp":
                        openTCPPorts.append([int(portService['port']), portService['service']])
                    elif portService['proto'] == "udp":
                        openUDPPorts.append([int(portService['port']), portService['service']])
                openTCPPorts.sort()
                openUDPPorts.sort()

    # display in both cases only if the list isn't empty
                if len(openTCPPorts) > 0:
                    line('h3', 'Open TCP Ports and Services')
                    with tag('table'):
                        with tag('tr'):
                            line('td', 'Port')
                            line('td', 'Service')
                        for port, service in openTCPPorts:
                            with tag('tr'):
                                line('td', port)
                                line('td', service)

                if len(openUDPPorts) > 0:
                    line('h3', 'Open UDP Ports and Services')
                    with tag('table'):
                        with tag('tr'):
                            line('td', 'Port')
                            line('td', 'Service')
                        for port, service in openUDPPorts:
                            with tag('tr'):
                                line('td', port)
                                line('td', service)


    # make list of vulns found, and we'll go through them
    # one by one, collecting and formatting useful information
                cveList = []
                if 'oids' in details:
                    for oidItem in details['oids']:
                        oidObj = db.vulnerabilities.find_one({'oid': oidItem['oid']})
                        line('h3', oidObj['name'])
                        with tag('table'):
                            with tag('tr'):
                                line('td', 'Summary')
                                line('td', oidObj['summary'])
                            with tag('tr'):
                                line('td', 'Impact')
                                line('td', oidObj['impact'])

                    oidCves = db.vulnerabilities.find_one({'oid': oidItem['oid']})['cve']
                    for cve in oidCves:
                        cveList.append(cve)
                doc.stag('hr')
            print(doc.getvalue())
'''
    # The 'hostname' field is a list of 0 or more hostnames. Choose the first one, of
    # if there is nothing, an empty string.
            if details['hostnames'] != []:
                hostname = details['hostnames'][0]
            else:
                hostname = ""
    # assemble record into a line of CSV
            record = [ details['ip'], hostname, os, openTCPPorts, openUDPPorts, detectedServices, vulnCount, cveList]
    # print assembled CSV line to output file
            linewriter.writerow(record)

    # close CSV
    csvfile.close()
'''

main()
