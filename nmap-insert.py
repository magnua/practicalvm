#!/usr/bin/env python

# Iterate through an nmap output XML file
# and insert relevant information into a Mongo database
# IP addresses are considered authoritative identifiers of individual
# hosts, and if a host already exists in Mongo, data provided here will
# overwrite older data in the existing Mongo document.
#
# v0.1
# Andrew Magnusson

import mongo, xml

# print usage and exit
def usage:
    print '''
    Usage: $ nmap-insert.py <infile>
    '''
def main:
# find and open the output XML file

# Do this for each 'host' block in the output file

main()
