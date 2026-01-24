#!/bin/bash

# TODO Script to test live IPS capabilities for AF_PACKET. Starts a ping, starts suricata,
# checks stats and alerts. Then issues a reload with a new rule file, checks stats and
# new alerts. Then shuts suricata down.

# Call with following arguments:
# 1st: "2" or "3" to indicate the tpacket version.
# 2nd: runmode string (single/autofp/workers)

set -e
set -x

if [ $# -ne "2" ]; then
    echo "ERROR call with 2 args: runmode (single/autofp/workers) and yaml"
    exit 1;
fi

RUNMODE=$1
YAML=$2

# dump some info
echo "* printing some diagnostics..."
ip netns list
uname -a
ip r
echo "* printing some diagnostics... done"

NAMESPACES=$(ip netns list|cut -d' ' -f1)
for NS in $NAMESPACES; do
    ip netns delete $NS
done

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

# we'll be creating 3 namespaces: client, server and dut. Dut is where Suricata will run:
#
# [ client ]$clientif - $dutclientif[ dut ]$dutserverif - $serverif[ server ]
#
# By routing packets between the dut interfaces, Suricata becomes the router.
#
clientns=client
serverns=server
dutns=dut
clientip="10.10.10.2/24"
clientnet="10.10.10.0/24"
serverip='10.10.20.2/24'
servernet="10.10.20.0/24"
dutclientip="10.10.10.1/24"
dutserverip='10.10.20.1/24'
clientif=client
serverif=server
dutclientif=dut_client
dutserverif=dut_server

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

# bring up interfaces. All interfaces get IP's.

echo "* setup client interface..."
ip netns exec $clientns ip addr add $clientip dev ptp-$clientif
ip netns exec $clientns ip link set ptp-$clientif up
echo "* setup client interface... done"

echo "* setup server interface..."
ip netns exec $serverns ip addr add $serverip dev ptp-$serverif
ip netns exec $serverns ip link set ptp-$serverif up
echo "* setup server interface... done"

echo "* setup dut interfaces..."
ip netns exec $dutns ip addr add $dutclientip dev ptp-$dutclientif
ip netns exec $dutns ip addr add $dutserverip dev ptp-$dutserverif
ip netns exec $dutns ip link set ptp-$dutclientif up
ip netns exec $dutns ip link set ptp-$dutserverif up
echo "* setup dut interfaces... done"

echo "* setup client/server routes..."
# routes:
#
# client can reach servernet through the client side ip of the dut
via_ip=$(echo $dutclientip|cut -f1 -d'/')
ip netns exec $clientns ip route add $servernet via $via_ip dev ptp-$clientif
#
# server can reach clientnet through the server side ip of the dut
via_ip=$(echo $dutserverip|cut -f1 -d'/')
ip netns exec $serverns ip route add $clientnet via $via_ip dev ptp-$serverif
echo "* setup client/server routes... done"

echo "* enabling forwarding in the dut..."
# forward all
ip netns exec $dutns sysctl net.ipv4.ip_forward=1
ip netns exec $dutns iptables -I FORWARD 1 -j NFQUEUE
echo "* enabling forwarding in the dut... done"

# set first rule file
cp .github/workflows/netns/drop-icmp.rules suricata.rules
RULES="suricata.rules"

echo "* starting Suricata in the \"dut\" namespace..."
# Start Suricata, SIGINT after 120 secords. Will close it earlier through
# the unix socket.
timeout --kill-after=240 --preserve-status 120 \
    ip netns exec $dutns \
        ./src/suricata -c $YAML -l ./ -q 0 -v \
            --set default-rule-path=. --runmode=$RUNMODE -S $RULES &
SURIPID=$!
sleep 10
echo "* starting Suricata... done"

echo "* starting Caddy..."
# Start Caddy in the server namespace
timeout --kill-after=240 --preserve-status 120 \
    ip netns exec $serverns \
        caddy file-server --domain 10.10.20.2 --browse &
CADDYPID=$!
sleep 10
echo "* starting Caddy in the \"server\" namespace... done"

echo "* running curl in the \"client\" namespace..."
ip netns exec $clientns \
    curl -O https://10.10.20.2/index.html
echo "* running curl in the \"client\" namespace... done"

echo "* running wget in the \"client\" namespace..."
ip netns exec $clientns \
    wget https://10.10.20.2/index.html
echo "* running wget in the \"client\" namespace... done"

echo "* running ping in the \"client\" namespace..."
set +e
ip netns exec $clientns \
    ping -c 10 10.10.10.20
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

# check stats and alerts
STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.ips.accepted > 0')
if [ $STATSCHECK = false ]; then
    echo "ERROR no packets captured"
    RES=1
fi
STATSCHECK=$(jq -c 'select(.event_type == "stats")' ./eve.json | tail -n1 | jq '.stats.ips.blocked != 10')
if [ $STATSCHECK = false ]; then
    echo "ERROR should have seen 10 blocked"
    RES=1
fi

kill -INT $CADDYPID
wait $CADDYPID
ip netns exec $dutns \
    ${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID

cat ./eve.json | jq -c 'select(.tls)'|tail -n1|jq
cat ./eve.json | jq -c 'select(.stats)|.stats.ips'|tail -n1|jq

echo "* done: $RES"
exit $RES
