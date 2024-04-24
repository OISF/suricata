#!/bin/bash

#set -e
set -x

ip r

RES=0
IFACE=$(ip r|grep default|awk '{print $5}')
echo $IFACE
GW=$(ip r|grep default|awk '{print $3}')
echo $GW

ping $GW &
PINGPID=$!

cp .github/workflows/live/icmp.rules suricata.rules

timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c suricata.yaml -l ./ --af-packet=$IFACE -v --set af-packet.1.tpacket-v3=false --set default-rule-path=. &
SURIPID=$!

sleep 15

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

cp .github/workflows/live/icmp2.rules suricata.rules

export PYTHONPATH=python/
python3 python/bin/suricatasc -c "reload-rules" /var/run/suricata/suricata-command.socket

sleep 15

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

echo "Done: $RES"
exit $RES
