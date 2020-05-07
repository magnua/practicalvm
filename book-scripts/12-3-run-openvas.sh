#!/bin/bash
OUTPUT=/home/andy/output
TS=`date +%Y%m%d`

# run-openvas.sh
# v0.1
# Andrew Magnusson

# must be run as scanuser or otherwise pointing to omp.config

#TARGET=e8b2417d-af95-4cda-9e35-36dda50896b5
#CONFIG=daba56c8-73ec-11df-a475-002264764cea
#TASKID=d0bab8b8-0d03-419d-ae5f-6756a8de051c
TASKID=59380858-1c32-438c-9c8c-e705c6c718da
OMPCONFIG="--config-file=/home/andy/omp.config"

# create task
#TASKID=`omp -C --target=$TARGET --config=$CONFIG --name="Scheduled Scan"`
#echo "Created task $TASKID"

# run task and get report ID
REPORTID=`omp $OMPCONFIG --start-task $TASKID | xmllint --xpath '/start_task_response/report_id/text()' -`
echo "Got report id $REPORTID"

# monitor task
while true; do
    sleep 120
    STATUS=`omp $OMPCONFIG -R $TASKID | xmllint --xpath 'get_tasks_response/task/status/text()' -`
    if [ "$STATUS" = "Done" ]; then
        # generate output
        omp $OMPCONFIG -X '<get_reports report_id="'$REPORTID'"/>'|xmllint --format - > $OUTPUT/openvas-$TS.xml
        echo "Output XML to $OUTPUT/openvas-$TS.xml"
        break
    fi
done
