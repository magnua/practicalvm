#!/usr/bin/env python3

# Cleans up the database by deleting untouched records older than
# a certain date. By default this script assumes anything older than 28
# days is stale and can be removed.
# v0.1
# Andrew Magnusson

from pymongo import MongoClient
import datetime, sys

# globals
# Mongo connection parameters
client = MongoClient('mongodb://localhost:27017')
db = client['vulnmgt']

# Number of days after which data is considered stale
olderThan = 28

# print usage and exit
def usage():
    print ('''
Usage: $ db-clean.py

    ''')

def main():

    # get the current date to determine how old is too old
    date = datetime.datetime.utcnow()
    oldDate = date - datetime.timedelta(days=olderThan)

    # now delete all records older than that date.

    hostsremoved = db.hosts.find({'updated': {'$lt': oldDate}}).count()
    #db.hosts.remove({'updated': {'$lt': oldDate}})

    print("Stale hosts removed:", hostsremoved)

main()
