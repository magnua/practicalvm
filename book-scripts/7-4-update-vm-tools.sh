#!/bin/bash
# Update the following line to point to your cve-search directory
CVE_SEARCH_DIR=/home/andy/cve-search

# Update the following line to point to your desired log file
LOG=/home/andy/output.log

# this clears the log file by overwriting it with a single
# line containing the date and time to an empty file
date > ${LOG}
# Update OpenVAS data
greenbone-nvt-sync >> ${LOG}
greenbone-scapdata-sync >> ${LOG}
greenbone-certdata-sync >> ${LOG}
service openvas-scanner restart >> ${LOG}
service openvas-manager restart >> ${LOG}
openvasmd --rebuild >> ${LOG}

# Update cve-search data
${CVE_SEARCH_DIR}/sbin/db_updater.py -v >> ${LOG}

# Update system, including OpenVAS
apt-get -y update >> ${LOG}

# Update Metasploit Framework
msfupdate >> ${LOG}

# This add a line to indicate that the update process is done
echo Update process done. >> ${LOG}

