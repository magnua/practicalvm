#!/usr/bin/env python3

# Detailed asset report
# Runs against a customizable IP address range or 0.0.0.0
# Output is in HTML format
# v0.1
# Andrew Magnusson

from pymongo import MongoClient
from operator import itemgetter
import datetime, sys, ipaddress
from yattag import Doc, indent

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
    # this modified sort uses the 'accuracy' item within the object as the sort key.
                    osList.sort(key=itemgetter('accuracy'))
                    os = osList[0]['osname']
                    cpe = osList[0]['cpe'][0]
                else:
                    os = "Unknown"
                    cpe = "None"
    # Generate a string of all known hostnames, if any
                hostnameString = ""
                if details['hostnames'] != []:
                    for name in details['hostnames']:
                        hostnameString += name + ', '

                line('h2', ip)
                line('b', 'Hostname(s): ')
                text(hostnameString)
                doc.stag('br')
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
    # one by one, collecting and formatting useful information.
    # Unfortunately, the fields in 'tags' in the original vulnerability
    # report from OpenVAS are all optional, so we'll need to test that
    # our desired fields exist before pulling them out.
                if 'oids' in details:
                    line('h3', 'Known Vulnerabilities')
                    for oidItem in details['oids']:
                        oidObj = db.vulnerabilities.find_one({'oid': oidItem['oid']})
                        line('h4', oidObj['name'])
                        with tag('p'):
                            text('OID: ')
                            line('i', oidObj['oid'])
                        with tag('table'):
                            with tag('tr'):
                                line('td', 'Summary')
                                if 'summary' in oidObj:
                                    line('td', oidObj['summary'])
                                else:
                                    line('td', "")
                            with tag('tr'):
                                line('td', 'Impact')
                                if 'impact' in oidObj:
                                    line('td', oidObj['impact'])
                                else:
                                    line('td', "")
                            with tag('tr'):
                                line('td', 'CVSS')
                                line('td', oidObj['cvss'])
                            with tag('tr'):
                                line('td', 'CVSS Base Vector')
                                line('td', oidObj['cvss_base_vector'])

    # for each associated CVE, print it out with basic information
    # TODO: pull more info from cvedb
                    oidCves = db.vulnerabilities.find_one({'oid': oidItem['oid']})['cve']
                    if oidCves != ['NOCVE']:
                        line('h5', 'Associated CVE(s):')
                        with tag('ul'):
                            for cve in oidCves:
                                line('li', cve)
                doc.stag('hr')

    # loop is over, time to write the output file.
    # the 'indent' function will make the source more readable.

    with open(outputFile, 'w') as htmlOut:
        htmlOut.write(indent(doc.getvalue()))
        htmlOut.close()

main()
