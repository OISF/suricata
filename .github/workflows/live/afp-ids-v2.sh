#!/bin/bash

RES=0
IFACE=$(ip r|grep default|awk '{print $5}')
echo $IFACE

ping suricata.io &
PINGPID=$!

cp .github/workflows/live/icmp.rules suricata.rules

timeout --kill-after=120 --preserve-status 10 \
    ./src/suricata -c suricata.yaml -l ./ --af-packet=$IFACE -v --set af-packet.1.tpacket-v3=false --set default-rule-path=. &
SURIPID=$!

sleep 5

STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.kernel_packets > 0')
if [ $STATSCHECK  = false ]; then
    echo "ERROR no packets captured"
    RES=1
fi

echo "SURIPID $SURIPID PINGPID $PINGPID"

# will fail currently as -S and reloads don't mix
export PYTHONPATH=python/
python3 python/bin/suricatasc -c "reload-rules" /var/run/suricata/suricata-command.socket

kill -INT $PINGPID
wait $PINGPID
python3 python/bin/suricatasc -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID

echo "Done: $RES"
exit $RES
