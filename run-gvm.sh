#!/bin/bash
OUTPUT=/home/andy/output
TS=`date +%Y%m%d`

# run-openvas.sh
# v0.2
# Andrew Magnusson

# Updated 1/1/2021 to use `gvm-cli` rather than `omp`

# get task ID of the scan you want to run
TASKID=c0e12f87-9e5b-44ea-820b-c9471db66dfb
GMPCONFIG="-c /home/andy/gmp.config socket"

# run task and get report ID
REPORTID=`gvm-cli $GMPCONFIG -X "<start_task task_id=\"$TASKID\"/>" | xmllint --xpath '/start_task_response/report_id/text()' -`
echo "Got report id $REPORTID"

# monitor task
while true; do
    sleep 120
    STATUS=`gvm-cli $GMPCONFIG -X "<get_tasks task_id=\"$TASKID\"/>" | xmllint --xpath 'get_tasks_response/task/status/text()' -`
    if [ "$STATUS" = "Done" ]; then
        # generate output
        gvm-cli $GMPCONFIG -X '<get_reports report_id="'$REPORTID'" details="1"/>' --pretty > $OUTPUT/gvm-$TS.xml
        echo "Output XML to $OUTPUT/gvm-$TS.xml"
        break
    fi
done
