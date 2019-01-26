#!/bin/bash

# automation.sh
# v0.1
# Andrew Magnusson

# Preferably run as root due to Nmap requirements


TS=`date +%Y%m%d`
SCRIPTS=/home/andy/scripts
OUTPUT=/home/andy/output
RANGE="10.0.0.0/24"

# Update the following line to point to your desired log file
LOG=/home/andy/output-$TS.log

# this clears the log file by overwriting it with a single
# line containing the date and time to an empty file
date > ${LOG}

nmap -A -oX $OUTPUT/nmap-$TS.xml $RANGE >> $LOG

$SCRIPTS/nmap-insert.py $OUTPUT/nmap-$TS.xml >> $LOG

# ensure u/p are set in ~/omp.config
$SCRIPTS/run-openvas.sh >> $LOG

$SCRIPTS/openvas-insert.py $OUTPUT/openvas-$TS.xml >> $LOG

$SCRIPTS/asset-report.py >> $LOG
mv $SCRIPTS/asset-report.csv $OUTPUT/asset-report-$TS.csv
$SCRIPTS/vuln-report.py >> $LOG
mv $SCRIPTS/vuln-report.csv $OUTPUT/vuln-report-$TS.csv

echo "Finished." >> $LOG
