#!/bin/bash

# Script to test live IDS capabilities for AF_PACKET using OVS span.
#
# Uses 3 network namespaces:
# - client
# - server
# - dut
#
# Dut is where Suricata will run:
#
# [ client ]$clientif - [ ovs ] - $serverif[ server ]
#                          \
#              span port -> \
#                            \ $dutif[ dut ]
#

# Call with following arguments:
# 1st: "2" or "3" to indicate the tpacket version.
# 2nd: runmode string (single/autofp/workers)
# 3rd: suricata yaml to use

#set -e
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
dutif=dut
ovsbridge=ovs-bridge

echo "* ovs delete"
OVS_BRIDGES=$(ovs-vsctl list-br)
for B in $OVS_BRIDGES; do
	if [ $B = "$ovsbridge" ]; then
		ovs-vsctl del-br $ovsbridge
	fi
done
echo "* ovs adding"
ovs-vsctl add-br $ovsbridge
echo "* ovs done"
ovs-vsctl list-br

echo "* removing old namespaces..."
NAMESPACES=$(ip netns list|cut -d' ' -f1)
for NS in $NAMESPACES; do
    if [ $NS = $dutns ] || [ $NS = $clientns ] || [ $NS = $serverns ]; then
        ip netns delete $NS
    fi
done
echo "* removing old namespaces... done"

ip link
ip address
ip route

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
ip link add $clientif type veth peer name ovs-$clientif
ip link add $serverif type veth peer name ovs-$serverif
ip link add $dutif type veth peer name ovs-$dutif
echo "* creating virtual ethernet devices...done"

echo "* list interface in global namespace..."
ip link
echo "* list interface in global namespace... done"

echo "* map virtual ethernet interfaces to their namespaces..."
ip link set $clientif netns $clientns
ip link set $serverif netns $serverns
ip link set $dutif netns $dutns
echo "* map virtual ethernet interfaces to their namespaces... done"

echo "* list namespaces and interfaces within them..."
ip netns list
ip netns exec $clientns ip ad
ip netns exec $serverns ip ad
ip netns exec $dutns ip ad
echo "* list namespaces and interfaces within them... done"

echo "* ovs adding ports..."
ovs-vsctl add-port $ovsbridge ovs-$clientif
ovs-vsctl add-port $ovsbridge ovs-$serverif
ovs-vsctl add-port $ovsbridge ovs-$dutif \
    -- --id=@p get port ovs-$dutif \
    -- --id=@m create mirror name=m0 select-all=true output-port=@p \
    -- set bridge $ovsbridge mirrors=@m
echo "* ovs adding ports... done"

ovs-vsctl list-br
ovs-vsctl list-ports $ovsbridge

ip link set dev ovs-$clientif up
ip link set dev ovs-$serverif up
ip link set dev ovs-$dutif up

echo "* setup client interface..."
ip netns exec $clientns ip addr add $clientip dev $clientif
ip netns exec $clientns ip link set $clientif up
echo "* setup client interface... done"

echo "* setup server interface..."
ip netns exec $serverns ip addr add $serverip dev $serverif
ip netns exec $serverns ip link set $serverif up
echo "* setup server interface... done"

echo "* setup dut interface..."
ip netns exec $dutns ip link set $dutif up
echo "* setup dut interface... done"

# set first rule file
cp .github/workflows/netns/alert-icmp.rules suricata.rules
RULES="suricata.rules"

echo "* starting Suricata in the \"dut\" namespace..."
# Start Suricata in the dut namespace, then SIGINT after 240 secords. Will
# close it earlier through the unix socket.
timeout --kill-after=300 --preserve-status 240 \
    ip netns exec $dutns \
        ./src/suricata -c $YAML -l ./ --af-packet=$dutif -v \
            --set default-rule-path=. --runmode=$RUNMODE -S $RULES &
SURIPID=$!
sleep 10
echo "* starting Suricata... done"

echo "* starting tshark on in the server namespace..."
timeout --kill-after=240 --preserve-status 180 \
    ip netns exec $serverns \
        tshark -i $serverif -T json > tshark-server.json &
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
if [ $PINGRES != 0 ]; then
    echo "ERROR ping should have succeeded"
    RES=1
fi

# give stats time to get updated
sleep 10

echo "* shutting down tshark..."
kill -INT $TSHARKSERVERPID
wait $TSHARKSERVERPID
echo "* shutting down tshark... done"

KERNEL_PACKETS=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.capture.kernel_packets')
echo "KERNEL_PACKETS $KERNEL_PACKETS"

if [ $KERNEL_PACKETS -eq 0 ]; then
    echo "ERROR no packets captured"
    RES=1
fi

# validate that we didn't receive pings
SERVER_RECV_PING=$(jq -c '.[]' ./tshark-server.json|jq -c 'select(._source.layers.icmp."icmp.type"=="8")'|wc -l)
echo "* server pings received check (should be 10): $SERVER_RECV_PING"
if [ $SERVER_RECV_PING -ne 10 ]; then
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
cat ./eve.json | jq -c 'select(.stats)|.stats.capture'|tail -n1|jq
#cat ./eve.json | jq
echo "* dumping some stats... done"

echo "* cleaning up..."
ovs-vsctl del-port $ovsbridge ovs-$clientif
ovs-vsctl del-port $ovsbridge ovs-$serverif
ovs-vsctl del-port $ovsbridge ovs-$dutif
ovs-vsctl del-br $ovsbridge
ip link delete dev ovs-$clientif
ip link delete dev ovs-$serverif
ip link delete dev ovs-$dutif
echo "* cleaning up... done"

echo "* removing old namespaces..."
NAMESPACES=$(ip netns list|cut -d' ' -f1)
for NS in $NAMESPACES; do
    if [ $NS = $dutns ] || [ $NS = $clientns ] || [ $NS = $serverns ]; then
	ip netns exec $NS ip link
        ip netns delete $NS
    fi
done
echo "* removing old namespaces... done"

echo "* done: $RES"
exit $RES
