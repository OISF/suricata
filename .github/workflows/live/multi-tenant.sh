#!/bin/bash

# Script that runs through basic MT operations:
# - Enable MT for Suricata
# - Tenant registration via suricatasc
# - Tenant reload via suricatasc
# - Tenant deregistration via suricatasc

# Call with following argument:
# runmode string (single/autofp/workers)

SOCKET=/var/run/suricata/suricata-command.socket
function timed_command()
{
    local command="$1"; shift
    local expected=${1:-"OK"}; shift
    local timeout=${1:-60}
    local duration=${1:-30}
    JSON=$(timeout --kill-after=${timeout} ${duration} ${SURICATASC} -c "${command}" ${SOCKET})
    rc=$?
    if [ $rc -eq 124 ]; then
        echo "Timeout detected; exiting"
        exit 1
    fi
    result=$(echo $JSON | jq -r '.return')
    if [ $result != ${expected} ]; then
        echo "EXITing due to expected result mismatch: expected ${expected}; actual ${result}"
        exit 1
    fi
    echo ${JSON}
}

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
cp .github/workflows/live/{suricata-mt.yaml,tenant-1.yaml} .

# Start Suricata, SIGINT after 120 secords. Will close it earlier through
# the unix socket.
timeout --kill-after=240 --preserve-status 120 \
    ./src/suricata -c suricata.yaml --include suricata-mt.yaml -l ./ --pcap=$IFACE --set "pcap.bpf-filter=icmp" -v --set default-rule-path=. --runmode=$RUNMODE &
SURIPID=$!

sleep 15

JSON=$(timed_command "register-tenant 2 tenant-1.yaml")
echo $JSON

JSON=$(timed_command "reload-tenants")
echo $JSON

JSON=$(timed_command "register-tenant 3 tenant-1.yaml")
echo $JSON

JSON=$(timed_command "reload-tenants")
echo $JSON

JSON=$(timed_command "unregister-tenant 2")
echo $JSON

JSON=$(timed_command "unregister-tenant 3")
echo $JSON

JSON=$(timed_command "unregister-tenant 5" "NOK")
echo $JSON

echo "SURIPID $SURIPID PINGPID $PINGPID"

JSON=$(timed_command "reload-tenants")

kill -INT $PINGPID
wait $PINGPID
${SURICATASC} -c "shutdown" ${SOCKET}
wait $SURIPID

echo "done: $RES"
exit $RES
