#!/usr/bin/env python3

# (Very) simple API to get information from the VM system
# Accepts GET requests of the following URL structures:
# /hosts/, /hosts/{id}
# /vulnerabilities/, /vulnerabilities/{id}

# v0.2
# Andrew Magnusson

import http.server, socketserver, json, re, ipaddress
from bson.json_util import dumps # for encoding mongo results
from pymongo import MongoClient
from io import BytesIO # for encoding responses

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
        response = db.hosts.find_one({'ip': hostid})
        if response:
            cveList = []
            oids = db.hosts.distinct('oids.oid', {'ip': hostid})
            for oid in oids:
                oidInfo = db.vulnerabilities.find_one({'oid': oid})
                if 'cve' in oidInfo.keys():
                    cveList += oidInfo['cve']
            cveList = sorted(set(cveList)) # sort, remove dupes
            if 'NOCVE' in cveList:
                cveList.remove('NOCVE') # remove NOCVE
            response['cves'] = cveList
        else:
            response = [{'error': 'IP ' + hostid + ' not found'}]
            code = ERRORCODE
    except ValueError as e:
        response= [{'error': str(e)}]
        code = ERRORCODE
    return code, dumps(response)

def getVulnDetails(cveid):
    code = 200
    # check if it's in the format CVE-XXXX-XXXX[XX]
    if (re.fullmatch('CVE-\d{4}-\d{4,}', cveid)):
        response = db.vulnerabilities.find_one({'cve': cveid})
        if response: # there's a cve in there
            oid = response['oid']
            result = db.hosts.distinct('ip', {'oids.oid': oid})
            response['affectedhosts'] = result
        else:
            response = [{'error': 'no hosts affected by ' + cveid}]
            code = ERRORCODE
    else:
        response = [{'error': cveid + ' is not a valid CVE ID'}]
        code = ERRORCODE
    return code, dumps(response)

def listHosts():
    results = db.hosts.distinct('ip')
    count = len(results)
    response =  [{'count': count, 'iplist': results}]
    return json.dumps(response)

def listVulns():
    results = db.vulnerabilities.distinct('cve')
    if 'NOCVE' in results:
        results.remove('NOCVE') # we don't care about these
    count = len(results)
    response = [{'count': count, 'cvelist': results}]
    return json.dumps(response)

class SimpleRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        response = BytesIO()
        splitPath = self.path.split('/')
        if (splitPath[1] == 'vulnerabilities'):
            if(len(splitPath) == 2 or (len(splitPath) == 3  and splitPath[2] == '')):
                self.send_response(200)
                response.write(listVulns().encode())
            elif(len(splitPath) == 3):
                code, details = getVulnDetails(splitPath[2])
                self.send_response(code)
                response.write(details.encode())
            else:
                self.send_response(ERRORCODE)
                response.write(json.dumps([{'error': 'did you mean /vulnerabilities/?'}]).encode())
        elif (splitPath[1] == 'hosts'):
            if(len(splitPath) == 2 or (len(splitPath) == 3 and splitPath[2] == '')):
                self.send_response(200)
                response.write(listHosts().encode())
            elif(len(splitPath) == 3):
                code, details = getHostDetails(splitPath[2])
                self.send_response(code)
                response.write(details.encode())
            else:
                self.send_response(ERRORCODE)
                response.write(json.dumps([{'error': 'did you mean /hosts/?'}]).encode())
        else:
            self.send_response(ERRORCODE)
            response.write(json.dumps([{'error': 'unrecognized path ' + self.path}]).encode())
        self.end_headers()
        self.wfile.write(response.getvalue())

def main():
    Handler = SimpleRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()

main()