#!/bin/bash

# Script to test live IDS capabilities for AF_PACKET. Starts a ping, starts suricata,
# checks stats and alerts. Then issues a reload with a new rule file, checks stats and
# new alerts. Then shuts suricata down.

# Call with following arguments:
# 1st: "2" or "3" to indicate the tpacket version.
# 2nd: runmode string (single/autofp/workers)

#set -e
set -x

if [ $# -ne "2" ]; then
    echo "ERROR call with 2 args: tpacket version (2/3) and runmode (single/autofp/workers)"
    exit 1;
fi

TPACKET=$1
RUNMODE=$2

# dump some info
uname -a
ip r

# remove eve.json from previous run
if [ -f eve.json ]; then
    rm eve.json
fi

RES=0

# Get listen interface and "ping" target address
IFACE=$(ip r|grep default|awk '{print $5}')
echo $IFACE
GW=$(ip r|grep default|awk '{print $3}')
echo $GW

ping $GW &
PINGPID=$!

# set first rule file
cp .github/workflows/live/icmp.rules suricata.rules

if [ $TPACKET = "2" ]; then
    V3=true
else
    V3=false
fi

# Start Suricata, SIGINT after 120 secords. Will close it earlier through
# the unix socket.
timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c suricata.yaml -l ./ --af-packet=$IFACE -v --set af-packet.1.tpacket-v3=$V3 --set default-rule-path=. --runmode=$RUNMODE &
SURIPID=$!

sleep 15

# check stats and alerts
STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.kernel_packets > 0')
if [ $STATSCHECK = false ]; then
    echo "ERROR no packets captured"
    RES=1
fi
SID1CHECK=$(jq -c 'select(.event_type == "alert")' ./eve.json | tail -n1 | jq '.alert.signature_id == 1')
if [ $SID1CHECK = false ]; then
    echo "ERROR no alerts for sid 1"
    RES=1
fi

echo "SURIPID $SURIPID PINGPID $PINGPID"

# set second rule file for the reload
cp .github/workflows/live/icmp2.rules suricata.rules

# trigger the reload
export PYTHONPATH=python/
python3 python/bin/suricatasc -c "reload-rules" /var/run/suricata/suricata-command.socket

sleep 15

# check stats and alerts
STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.kernel_packets > 0')
if [ $STATSCHECK = false ]; then
    echo "ERROR no packets captured"
    RES=1
fi
SID2CHECK=$(jq -c 'select(.event_type == "alert")' ./eve.json | tail -n1 | jq '.alert.signature_id == 2')
if [ $SID2CHECK = false ]; then
    echo "ERROR no alerts for sid 2"
    RES=1
fi

kill -INT $PINGPID
wait $PINGPID
python3 python/bin/suricatasc -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID

echo "done: $RES"
exit $RES
