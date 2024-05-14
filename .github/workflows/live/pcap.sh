#!/bin/bash

# Script to test live IDS capabilities for OCAO. Starts a ping, starts suricata,
# checks stats and alerts. Then issues a reload with a new rule file, checks stats and
# new alerts. Then shuts suricata down.

# Call with following argument1:
# runmode string (single/autofp/workers)

#set -e
set -x

if [ $# -ne "1" ]; then
    echo "ERROR call with 1 args: runmode (single/autofp/workers)"
    exit 1;
fi

RUNMODE=$1

# dump some info
uname -a
ip r

# remove eve.json from previous run
if [ -f eve.json ]; then
    rm eve.json
fi

RES=0

export PYTHONPATH=python/
# Get listen interface and "ping" target address
IFACE=$(ip r|grep default|awk '{print $5}')
echo $IFACE
GW=$(ip r|grep default|awk '{print $3}')
echo $GW

ping $GW &
PINGPID=$!

# set first rule file
cp .github/workflows/live/icmp.rules suricata.rules

# Start Suricata, SIGINT after 120 secords. Will close it earlier through
# the unix socket.
timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c suricata.yaml -l ./ --pcap=$IFACE -v --set default-rule-path=. --runmode=$RUNMODE &
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
CHECK=$(jq -c 'select(.alert.signature_id == 222)' ./eve.json | wc -l)
if [ $CHECK -ne 1 ]; then
	echo "ERROR alerts count off for sid 222 (datasets)"
    RES=1
fi
JSON=$(python3 python/bin/suricatasc -v -c "dataset-clear ipv4-list ipv4" /var/run/suricata/suricata-command.socket)
echo $JSON

sleep 5
CHECK=$(jq -c 'select(.alert.signature_id == 222)' ./eve.json | wc -l)
if [ $CHECK -ne 2 ]; then
	echo "ERROR alerts count off for sid 222 (datasets)"
    RES=1
fi

echo "SURIPID $SURIPID PINGPID $PINGPID"

# set second rule file for the reload
cp .github/workflows/live/icmp2.rules suricata.rules

# trigger the reload
JSON=$(python3 python/bin/suricatasc -c "iface-list" /var/run/suricata/suricata-command.socket)
PIFACE=$(echo $JSON | jq -r .message.ifaces[0])
JSON=$(python3 python/bin/suricatasc -c "iface-stat $PIFACE")
STATSCHECK=$(echo $JSON | jq '.message.pkts > 0')
if [ $STATSCHECK = false ]; then
    echo "ERROR unix socket stats check failed"
    RES=1
fi
python3 python/bin/suricatasc -c "reload-rules" /var/run/suricata/suricata-command.socket


JSON=$(python3 python/bin/suricatasc -c "iface-bypassed-stat" /var/run/suricata/suricata-command.socket)
echo $JSON
JSON=$(python3 python/bin/suricatasc -c "capture-mode" /var/run/suricata/suricata-command.socket)
if [ "$(echo $JSON | jq -r .message)" != "PCAP_DEV" ]; then
    echo "ERROR unix socket capture mode check failed"
    RES=1
fi
JSON=$(python3 python/bin/suricatasc -c "dump-counters" /var/run/suricata/suricata-command.socket)
STATSCHECK=$(echo $JSON | jq '.message.uptime >= 15')
if [ $STATSCHECK = false ]; then
    echo "ERROR unix socket dump-counters uptime check failed"
    RES=1
fi
JSON=$(python3 python/bin/suricatasc -c "memcap-list" /var/run/suricata/suricata-command.socket)
echo $JSON
JSON=$(python3 python/bin/suricatasc -c "running-mode" /var/run/suricata/suricata-command.socket)
echo $JSON
if [ "$(echo $JSON | jq -r .message)" != "$RUNMODE" ]; then
    echo "ERROR unix socket runmode check failed"
    RES=1
fi
JSON=$(python3 python/bin/suricatasc -c "version" /var/run/suricata/suricata-command.socket)
echo $JSON
JSON=$(python3 python/bin/suricatasc -c "uptime" /var/run/suricata/suricata-command.socket)
echo $JSON
STATSCHECK=$(echo $JSON | jq '.message >= 15')
if [ $STATSCHECK = false ]; then
    echo "ERROR unix socket uptime check failed"
    RES=1
fi
sleep 15
JSON=$(python3 python/bin/suricatasc -c "add-hostbit $GW test 60" /var/run/suricata/suricata-command.socket)
echo $JSON

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
JSON=$(python3 python/bin/suricatasc -c "list-hostbit $GW" /var/run/suricata/suricata-command.socket)
CHECK=$(echo $JSON|jq -r .message.hostbits[0].name)
if [ "$CHECK" != "test" ]; then
    echo "ERROR hostbit listing failed"
    RES=1
fi
JSON=$(python3 python/bin/suricatasc -c "remove-hostbit $GW test" /var/run/suricata/suricata-command.socket)

kill -INT $PINGPID
wait $PINGPID
python3 python/bin/suricatasc -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID

echo "done: $RES"
exit $RES
