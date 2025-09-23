#!/bin/bash

# Script that runs through basic MT operations:
# - Enable MT for Suricata
# - Tenant registration via suricatasc
# - Tenant reload via suricatasc
# - Tenant deregistration via suricatasc

# Call with following argument:
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

if [ -e ./rust/target/release/suricatasc ]; then
    SURICATASC=./rust/target/release/suricatasc
else
    SURICATASC=./rust/target/debug/suricatasc
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
    ./src/suricata -c suricata.yaml --include suricata-mt.yaml -l ./ --pcap=$IFACE --set "pcap.bpf-filter=icmp" -v --set default-rule-path=. --runmode=$RUNMODE &
SURIPID=$!

sleep 15

JSON=$(${SURICATASC} -v -c "register-tenant 2 tenant-1.yaml  /var/run/suricata/suricata-command.socket)
echo $JSON


echo "SURIPID $SURIPID PINGPID $PINGPID"

${SURICATASC} -c "reload-tenants" /var/run/suricata/suricata-command.socket



kill -INT $PINGPID
wait $PINGPID
${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID

echo "done: $RES"
exit $RES
