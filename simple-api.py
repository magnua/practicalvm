#!/usr/bin/env python3

# (Very) simple API to get information from the VM system
# Accepts GET requests of the following URL structures:
# /hosts/list, /hosts/{id}
# /vulnerabilities/list, /vulnerabilities/{id}

import http.server
import socketserver
import json, re
from pymongo import MongoClient
import ipaddress # for ip checking
from io import BytesIO # for encoding responses
from urllib import parse

# globals
# Mongo connection parameters
client = MongoClient('mongodb://localhost:27017')
db = client['vulnmgt']
# HTTP parameters
PORT=8000
ERRORCODE=418 # I'm a teapot

def getHostDetails(hostid):
    code = 200
    # check if it's a valid ip
    try:
        ipaddress.ip_address(hostid)
        # TODO: build and return host details
        # including list of vulnerabilities
        response = [{'host': hostid, 'info': 'info goes here', 'vulnerabilities': ['CVE-XXXX-XXXX', 'CVE-YYYY-YYYY']}]
    except ValueError:
        response= [{'error': hostid + ' is not a valid IP address'}]
        code = ERRORCODE
    return code, json.dumps(response)

def getVulnDetails(cveid):
    code = 200
    # check if it's in the format CVE-XXXX-XXXX[XX]
    if (re.fullmatch('CVE-\d{4}-\d{4,}', cveid)):
        # TODO: build and return vulnerability details for CVE
        # including list of hosts vulnerable
        response = [{'cve': cveid, 'summary': 'summary goes here', 'affectedhosts': ['x.x.x.x', 'y.y.y.y']}]
    else:
        response = [{'error': cveid + ' is not a valid CVE ID'}]
        code = ERRORCODE
    return code, json.dumps(response)

def listHosts():
    results = db.hosts.distinct('ip')
    count = len(results)
    response =  [{'count': count, 'iplist': results}]
    return json.dumps(response)

def listVulns():
    results = db.vulnerabilities.distinct('cve')
    results.remove('NOCVE') # we don't care about these
    count = len(results)
    response = [{'count': count, 'cvelist': results}]
    return json.dumps(response)

class SimpleRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        response = BytesIO()
        splitPath = self.path.split('/')
        if (splitPath[1] == 'vulnerabilities'):
            if(splitPath[2] == 'list'):
                self.send_response(200)
                response.write(listVulns().encode())
            elif(splitPath[2]):
                code, details = getVulnDetails(splitPath[2])
                self.send_response(code)
                response.write(details.encode())
            else:
                self.send_response(ERRORCODE)
                response.write(json.dumps([{'error': 'did you mean /vulnerabilities/list?'}]).encode())
        elif (splitPath[1] == 'hosts'):
            if(splitPath[2] == 'list'):
                self.send_response(200)
                response.write(listHosts().encode())
            elif(splitPath[2]):
                code, details = getHostDetails(splitPath[2])
                self.send_response(code)
                response.write(details.encode())
            else:
                self.send_response(ERRORCODE)
                response.write(json.dumps([{'error': 'did you mean /hosts/list?'}]).encode())
        else:
            self.send_response(ERRORCODE)
            response.write(json.dumps([{'error': 'unrecognized path ' + self.path}]).encode())
        self.end_headers()
        
        self.wfile.write(response.getvalue())


Handler = SimpleRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
