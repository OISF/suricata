#!/bin/bash

# Script to test live IDS capabilities for DPDK using DPDK's null interface.
# Connects over unix socket. Issues a reload. Then shuts suricata down.

#set -e
set -x

if [ $# -ne "1" ]; then
    echo "ERROR call with 1 args: path to yaml to use"
    exit 1;
fi

YAML=$1

# dump some info
uname -a

# remove eve.json from previous run
if [ -f eve.json ]; then
    rm eve.json
fi

RES=0

# set first rule file
cp .github/workflows/live/icmp.rules suricata.rules

# Start Suricata, SIGINT after 120 secords. Will close it earlier through
# the unix socket.
timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c $YAML -l ./ --dpdk -v --set default-rule-path=. &
SURIPID=$!

sleep 15

# check stats and alerts
STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.packets > 0')
if [ $STATSCHECK = false ]; then
    echo "ERROR no packets captured"
    RES=1
fi

echo "SURIPID $SURIPID"

# set second rule file for the reload
cp .github/workflows/live/icmp2.rules suricata.rules

# trigger the reload
export PYTHONPATH=python/
python3 python/bin/suricatasc -c "reload-rules" /var/run/suricata/suricata-command.socket

sleep 15

# check stats and alerts
STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.packets > 0')
if [ $STATSCHECK = false ]; then
    echo "ERROR no packets captured"
    RES=1
fi

python3 python/bin/suricatasc -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID

echo "done: $RES"
exit $RES
