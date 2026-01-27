#!/bin/bash

# Script to test live IPS capabilities for AF_PACKET.
#
# Uses 3 network namespaces:
# - client
# - server
# - dut
#
# Dut is where Suricata will run:
#
# [ client ]$clientif - $dutclientif[ dut ]$dutserverif - $serverif[ server ]
#
# By copying packets between the dut interfaces, Suricata becomes the bridge.

# Call with following arguments:
# 1st: "2" or "3" to indicate the tpacket version.
# 2nd: runmode string (single/autofp/workers)
# 3rd: suricata yaml to use

set -e
set -x

if [ $# -ne "3" ]; then
    echo "ERROR call with 3 args: tpacket version (2/3), runmode (single/autofp/workers) and yaml"
    exit 1;
fi

TPACKET=$1
RUNMODE=$2
YAML=$3

# dump some info
echo "* printing some diagnostics..."
ip netns list
uname -a
ip r
echo "* printing some diagnostics... done"

clientns=client
serverns=server
dutns=dut
clientip="10.10.10.10/24"
serverip='10.10.10.20/24'
clientif=client
serverif=server
dutclientif=dut_client
dutserverif=dut_server

echo "* removing old namespaces..."
NAMESPACES=$(ip netns list|cut -d' ' -f1)
for NS in $NAMESPACES; do
    if [ $NS = $dutns ] || [ $NS = $clientns ] || [ $NS = $serverns ]; then
        ip netns delete $NS
    fi
done
echo "* removing old namespaces... done"

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

# adding namespaces
echo "* creating namespaces..."
ip netns add $clientns
ip netns add $serverns
ip netns add $dutns
echo "* creating namespaces... done"

#diagnostics output
echo "* list namespaces..."
ip netns list
ip netns exec $clientns ip ad
ip netns exec $serverns ip ad
ip netns exec $dutns ip ad
echo "* list namespaces... done"

# create virtual ethernet link between client-dut and server-dut
# These are not yet mapped to a namespace
echo "* creating virtual ethernet devices..."
ip link add ptp-$clientif type veth peer name ptp-$dutclientif
ip link add ptp-$serverif type veth peer name ptp-$dutserverif
echo "* creating virtual ethernet devices...done"

echo "* list interface in global namespace..."
ip link
echo "* list interface in global namespace... done"

echo "* map virtual ethernet interfaces to their namespaces..."
ip link set ptp-$clientif netns $clientns
ip link set ptp-$serverif netns $serverns
ip link set ptp-$dutclientif netns $dutns
ip link set ptp-$dutserverif netns $dutns
echo "* map virtual ethernet interfaces to their namespaces... done"

echo "* list namespaces and interfaces within them..."
ip netns list
ip netns exec $clientns ip ad
ip netns exec $serverns ip ad
ip netns exec $dutns ip ad
echo "* list namespaces and interfaces within them... done"

# bring up interfaces. Client and server get IP's.
# Disable rx and tx csum offload on all sides.

echo "* setup client interface..."
ip netns exec $clientns ip addr add $clientip dev ptp-$clientif
ip netns exec $clientns ethtool -K ptp-$clientif rx off tx off
ip netns exec $clientns ip link set ptp-$clientif up
echo "* setup client interface... done"

echo "* setup server interface..."
ip netns exec $serverns ip addr add $serverip dev ptp-$serverif
ip netns exec $serverns ethtool -K ptp-$serverif rx off tx off
ip netns exec $serverns ip link set ptp-$serverif up
echo "* setup server interface... done"

echo "* setup dut interfaces..."
ip netns exec $dutns ethtool -K ptp-$dutclientif rx off tx off
ip netns exec $dutns ethtool -K ptp-$dutserverif rx off tx off
ip netns exec $dutns ip link set ptp-$dutclientif up
ip netns exec $dutns ip link set ptp-$dutserverif up
echo "* setup dut interfaces... done"

# set first rule file
cp .github/workflows/netns/drop-icmp.rules suricata.rules
RULES="suricata.rules"

echo "* starting Suricata in the \"dut\" namespace..."
# Start Suricata in the dut namespace, then SIGINT after 240 secords. Will
# close it earlier through the unix socket.
timeout --kill-after=300 --preserve-status 240 \
    ip netns exec $dutns \
        ./src/suricata -c $YAML -l ./ --af-packet -v \
            --set default-rule-path=. --runmode=$RUNMODE -S $RULES &
SURIPID=$!
sleep 10
echo "* starting Suricata... done"

echo "* starting tshark on in the server namespace..."
timeout --kill-after=240 --preserve-status 180 \
    ip netns exec $serverns \
        tshark -i ptp-$serverif -T json > tshark-server.json &
TSHARKSERVERPID=$!
sleep 5
echo "* starting tshark on in the server namespace... done, pid $TSHARKSERVERPID"

echo "* starting Caddy..."
# Start Caddy in the server namespace
timeout --kill-after=240 --preserve-status 120 \
    ip netns exec $serverns \
        caddy file-server --domain 10.10.10.20 --browse &
CADDYPID=$!
sleep 10
echo "* starting Caddy in the \"server\" namespace... done"

echo "* running curl in the \"client\" namespace..."
ip netns exec $clientns \
    curl -O https://10.10.10.20/index.html
echo "* running curl in the \"client\" namespace... done"

echo "* running wget in the \"client\" namespace..."
ip netns exec $clientns \
    wget https://10.10.10.20/index.html
echo "* running wget in the \"client\" namespace... done"

ping_ip=$(echo $serverip|cut -f1 -d'/')
echo "* running ping $ping_ip in the \"client\" namespace..."
set +e
ip netns exec $clientns \
    ping -c 10 $ping_ip
PINGRES=$?
set -e
echo "* running ping in the \"client\" namespace... done"

# pings should have been dropped, so ping reports error
if [ $PINGRES != 1 ]; then
    echo "ERROR ping should have failed"
    RES=1
fi

# give stats time to get updated
sleep 10

echo "* shutting down tshark..."
kill -INT $TSHARKSERVERPID
wait $TSHARKSERVERPID
echo "* shutting down tshark... done"

ACCEPTED=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.ips.accepted')
BLOCKED=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.ips.blocked')
KERNEL_PACKETS=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.kernel_packets')
echo "ACCEPTED $ACCEPTED BLOCKED $BLOCKED KERNEL_PACKETS $KERNEL_PACKETS"

if [ $KERNEL_PACKETS -eq 0 ]; then
    echo "ERROR no packets captured"
    RES=1
fi
if [ $ACCEPTED -eq 0 ]; then
    echo "ERROR should have seen non-0 accepted"
    RES=1
fi
if [ $BLOCKED -ne 10 ]; then
    echo "ERROR should have seen 10 blocked"
    RES=1
fi

# validate that we didn't receive pings
SERVER_RECV_PING=$(jq -c '.[]' ./tshark-server.json|jq 'select(._source.layers.icmp."icmp.type"=="8")'|wc -l)
echo "* server pings received check (should be 0): $SERVER_RECV_PING"
if [ $SERVER_RECV_PING -ne 0 ]; then
    jq '.[]' ./tshark-server.json | jq 'select(._source.layers.icmp)'
    RES=1
fi
echo "* server pings received check... done"

echo "* shutting down..."
kill -INT $CADDYPID
wait $CADDYPID
ip netns exec $dutns \
    ${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID
echo "* shutting down... done"

echo "* dumping some stats..."
cat ./eve.json | jq -c 'select(.tls)'|tail -n1|jq
cat ./eve.json | jq -c 'select(.stats)|.stats.ips'|tail -n1|jq
cat ./eve.json | jq -c 'select(.stats)|.stats.capture'|tail -n1|jq
cat ./eve.json | jq
echo "* dumping some stats... done"


echo "* done: $RES"
exit $RES
