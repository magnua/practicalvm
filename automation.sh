#!/bin/bash

# automation.sh
# v0.2
# Andrew Magnusson

# 0.2: `run-openvas.sh` now runs as nonprivileged user

# Preferably run as root due to Nmap requirements

# comment this out if non-root/sudo is okay
if [ $EUID != 0 ]; then
  echo "Please run as root"
  exit 1
fi

TS=`date +%Y%m%d`
SCRIPTS=/home/andy/scripts
OUTPUT=/home/andy/output
RANGE="10.0.0.0/24"

# Update the following line to point to your desired log file
LOG=/home/andy/output-$TS.log

# this clears the log file by overwriting it with a single
# line containing the date and time to an empty file
date > ${LOG}

nmap -A -O -oX $OUTPUT/nmap-$TS.xml $RANGE >> $LOG

$SCRIPTS/nmap-insert.py $OUTPUT/nmap-$TS.xml >> $LOG

# ensure u/p are set in ~/gmp.config
# `gmp-cli` will not run as root
sudo -u ubuntu $SCRIPTS/run-gvm.sh >> $LOG

$SCRIPTS/gvm-insert.py $OUTPUT/gvm-$TS.xml >> $LOG

$SCRIPTS/asset-report.py >> $LOG
mv $SCRIPTS/asset-report.csv $OUTPUT/asset-report-$TS.csv
$SCRIPTS/vuln-report.py >> $LOG
mv $SCRIPTS/vuln-report.csv $OUTPUT/vuln-report-$TS.csv

echo "Running database cleanup script." >> $LOG
$SCRIPTS/db-clean.py

echo "Finished." >> $LOG
