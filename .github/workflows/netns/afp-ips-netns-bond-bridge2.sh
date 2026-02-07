#!/bin/bash

# Script to test live IPS capabilities for AF_PACKET. Test with multiple networks and multiple
# bonds all handled by a single suricata.
#
# Uses 3 network namespaces:
# - client
# - server
# - dut
#
# Dut is where Suricata will run:
#
# [ client1 ]$clientif1 \      / $dutclientif1[     ]$dutserverif1 \      / $serverif1[ server1 ]
# [         ]#clientif2 - bond - $dutclientif2[     ]$dutserverif2 - bond - $serverif2[         ]
#                                             [ dut ]
# [ client2 ]$clientif1 - bond - $dutclientif1[     ]$dutserverif1 - bond - $serverif1[ server2 ]
# [         ]$clientif2 /      \ $dutclientif2[     ]$dutserverif2 /      \ $serverif2[         ]
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

dutns=dut
clientns1=client1
serverns1=server1
clientip1="10.10.10.10/24"
serverip1='10.10.10.20/24'
clientif1=client1
serverif1=server1
dutclientif1=dut1_clnt
dutserverif1=dut1_srvr
clientns2=client2
serverns2=server2
clientip2="10.20.10.10/24"
serverip2='10.20.10.20/24'
clientif2=client2
serverif2=server2
dutclientif2=dut2_clnt
dutserverif2=dut2_srvr
mtu=9000

echo "* removing old namespaces..."
NAMESPACES=$(ip netns list|cut -d' ' -f1)
for NS in $NAMESPACES; do
    if [ $NS = $dutns ] || [ $NS = $clientns1 ] || [ $NS = $serverns1 ] ||
	    [ $NS = $clientns2 ] || [ $NS = $serverns2 ]; then
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
ip netns add $clientns1
ip netns add $serverns1
ip netns add $clientns2
ip netns add $serverns2
ip netns add $dutns
echo "* creating namespaces... done"

#diagnostics output
echo "* list namespaces..."
ip netns list
ip netns exec $clientns1 ip ad
ip netns exec $serverns1 ip ad
ip netns exec $clientns1 ip ad
ip netns exec $serverns1 ip ad
ip netns exec $dutns ip ad
echo "* list namespaces... done"

# create virtual ethernet link between client-dut and server-dut
# These are not yet mapped to a namespace
echo "* creating virtual ethernet devices..."
ip link add ptp-a$clientif1 type veth peer name ptp-a$dutclientif1
ip link add ptp-b$clientif1 type veth peer name ptp-b$dutclientif1
ip link add ptp-a$serverif1 type veth peer name ptp-a$dutserverif1
ip link add ptp-b$serverif1 type veth peer name ptp-b$dutserverif1

ip link add ptp-a$clientif2 type veth peer name ptp-a$dutclientif2
ip link add ptp-b$clientif2 type veth peer name ptp-b$dutclientif2
ip link add ptp-a$serverif2 type veth peer name ptp-a$dutserverif2
ip link add ptp-b$serverif2 type veth peer name ptp-b$dutserverif2
echo "* creating virtual ethernet devices...done"

echo "* list interface in global namespace..."
ip link
echo "* list interface in global namespace... done"

echo "* map virtual ethernet interfaces to their namespaces..."
ip link set ptp-a$clientif1 netns $clientns1
ip link set ptp-b$clientif1 netns $clientns1

ip link set ptp-a$serverif1 netns $serverns1
ip link set ptp-b$serverif1 netns $serverns1

ip link set ptp-a$dutclientif1 netns $dutns
ip link set ptp-b$dutclientif1 netns $dutns
ip link set ptp-a$dutserverif1 netns $dutns
ip link set ptp-b$dutserverif1 netns $dutns

ip link set ptp-a$clientif2 netns $clientns2
ip link set ptp-b$clientif2 netns $clientns2

ip link set ptp-a$serverif2 netns $serverns2
ip link set ptp-b$serverif2 netns $serverns2

ip link set ptp-a$dutclientif2 netns $dutns
ip link set ptp-b$dutclientif2 netns $dutns
ip link set ptp-a$dutserverif2 netns $dutns
ip link set ptp-b$dutserverif2 netns $dutns
echo "* map virtual ethernet interfaces to their namespaces... done"

echo "* setting mtu to $mtu"
ip netns exec $clientns1 ip link set ptp-a$clientif1 mtu $mtu
ip netns exec $clientns1 ip link set ptp-b$clientif1 mtu $mtu
ip netns exec $serverns1 ip link set ptp-a$serverif1 mtu $mtu
ip netns exec $serverns1 ip link set ptp-b$serverif1 mtu $mtu
ip netns exec $dutns ip link set ptp-a$dutclientif1 mtu $mtu
ip netns exec $dutns ip link set ptp-b$dutclientif1 mtu $mtu
ip netns exec $dutns ip link set ptp-a$dutserverif1 mtu $mtu
ip netns exec $dutns ip link set ptp-b$dutserverif1 mtu $mtu

ip netns exec $clientns2 ip link set ptp-a$clientif2 mtu $mtu
ip netns exec $clientns2 ip link set ptp-b$clientif2 mtu $mtu
ip netns exec $serverns2 ip link set ptp-a$serverif2 mtu $mtu
ip netns exec $serverns2 ip link set ptp-b$serverif2 mtu $mtu
ip netns exec $dutns ip link set ptp-a$dutclientif2 mtu $mtu
ip netns exec $dutns ip link set ptp-b$dutclientif2 mtu $mtu
ip netns exec $dutns ip link set ptp-a$dutserverif2 mtu $mtu
ip netns exec $dutns ip link set ptp-b$dutserverif2 mtu $mtu
echo "* setting mtu to $mtu... done"

# bonds need to be created in the namespace
echo "* creating bonds..."
ip netns exec $clientns1 ip link add bond-$clientif1 type bond mode active-backup
ip netns exec $clientns1 ip link set ptp-a$clientif1 master bond-$clientif1
ip netns exec $clientns1 ip link set ptp-b$clientif1 master bond-$clientif1
ip netns exec $clientns1 ip link set bond-$clientif1 mtu $mtu

ip netns exec $dutns ip link add bond-$dutclientif1 type bond mode active-backup
ip netns exec $dutns ip link set ptp-a$dutclientif1 master bond-$dutclientif1
ip netns exec $dutns ip link set ptp-b$dutclientif1 master bond-$dutclientif1
ip netns exec $dutns ip link set bond-$dutclientif1 mtu $mtu

ip netns exec $serverns1 ip link add bond-$serverif1 type bond mode active-backup
ip netns exec $serverns1 ip link set ptp-a$serverif1 master bond-$serverif1
ip netns exec $serverns1 ip link set ptp-b$serverif1 master bond-$serverif1
ip netns exec $serverns1 ip link set bond-$serverif1 mtu $mtu

ip netns exec $dutns ip link add bond-$dutserverif1 type bond mode active-backup
ip netns exec $dutns ip link set ptp-a$dutserverif1 master bond-$dutserverif1
ip netns exec $dutns ip link set ptp-b$dutserverif1 master bond-$dutserverif1
ip netns exec $dutns ip link set bond-$dutserverif1 mtu $mtu

ip netns exec $clientns2 ip link add bond-$clientif2 type bond mode active-backup
ip netns exec $clientns2 ip link set ptp-a$clientif2 master bond-$clientif2
ip netns exec $clientns2 ip link set ptp-b$clientif2 master bond-$clientif2
ip netns exec $clientns2 ip link set bond-$clientif2 mtu $mtu

ip netns exec $dutns ip link add bond-$dutclientif2 type bond mode active-backup
ip netns exec $dutns ip link set ptp-a$dutclientif2 master bond-$dutclientif2
ip netns exec $dutns ip link set ptp-b$dutclientif2 master bond-$dutclientif2
ip netns exec $dutns ip link set bond-$dutclientif2 mtu $mtu

ip netns exec $serverns2 ip link add bond-$serverif2 type bond mode active-backup
ip netns exec $serverns2 ip link set ptp-a$serverif2 master bond-$serverif2
ip netns exec $serverns2 ip link set ptp-b$serverif2 master bond-$serverif2
ip netns exec $serverns2 ip link set bond-$serverif2 mtu $mtu

ip netns exec $dutns ip link add bond-$dutserverif2 type bond mode active-backup
ip netns exec $dutns ip link set ptp-a$dutserverif2 master bond-$dutserverif2
ip netns exec $dutns ip link set ptp-b$dutserverif2 master bond-$dutserverif2
ip netns exec $dutns ip link set bond-$dutserverif2 mtu $mtu
echo "* creating bonds... done"

echo "* list namespaces and interfaces within them..."
ip netns list
ip netns exec $clientns1 ip ad
ip netns exec $serverns1 ip ad
ip netns exec $clientns2 ip ad
ip netns exec $serverns2 ip ad
ip netns exec $dutns ip ad
echo "* list namespaces and interfaces within them... done"

# bring up interfaces. Client and server get IP's.
# Disable rx and tx csum offload on all sides.

echo "* setup client interfaces..."
ip netns exec $clientns1 ip addr add $clientip1 dev bond-$clientif1
ip netns exec $clientns1 ethtool -K bond-$clientif1 rx off tx off
ip netns exec $clientns1 ip link set bond-$clientif1 up

ip netns exec $clientns2 ip addr add $clientip2 dev bond-$clientif2
ip netns exec $clientns2 ethtool -K bond-$clientif2 rx off tx off
ip netns exec $clientns2 ip link set bond-$clientif2 up
echo "* setup client interfaces... done"

echo "* setup server interfaces..."
ip netns exec $serverns1 ip addr add $serverip1 dev bond-$serverif1
ip netns exec $serverns1 ethtool -K bond-$serverif1 rx off tx off
ip netns exec $serverns1 ip link set bond-$serverif1 up

ip netns exec $serverns2 ip addr add $serverip2 dev bond-$serverif2
ip netns exec $serverns2 ethtool -K bond-$serverif2 rx off tx off
ip netns exec $serverns2 ip link set bond-$serverif2 up
echo "* setup server interfaces... done"

echo "* setup dut interfaces..."
ip netns exec $dutns ethtool -K bond-$dutclientif1 rx off tx off
ip netns exec $dutns ethtool -K bond-$dutserverif1 rx off tx off
ip netns exec $dutns ip link set bond-$dutclientif1 up
ip netns exec $dutns ip link set bond-$dutserverif1 up

ip netns exec $dutns ethtool -K bond-$dutclientif2 rx off tx off
ip netns exec $dutns ethtool -K bond-$dutserverif2 rx off tx off
ip netns exec $dutns ip link set bond-$dutclientif2 up
ip netns exec $dutns ip link set bond-$dutserverif2 up
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
    ip netns exec $serverns1 \
        tshark -i bond-$serverif1 -T json > tshark-server.json &
TSHARKSERVERPID=$!
sleep 5
echo "* starting tshark on in the server namespace... done, pid $TSHARKSERVERPID"

echo "* starting Caddy..."
# Start Caddy in the server namespace
timeout --kill-after=240 --preserve-status 120 \
    ip netns exec $serverns1 \
        caddy file-server --domain 10.10.10.20 --browse &
CADDYPID=$!
sleep 10
echo "* starting Caddy in the \"server1\" namespace... done"

echo "* starting Caddy..."
# Start Caddy in the server namespace
timeout --kill-after=240 --preserve-status 120 \
    ip netns exec $serverns2 \
        caddy file-server --domain 10.20.10.20 --browse &
CADDYPID2=$!
sleep 10
echo "* starting Caddy in the \"server2\" namespace... done"

echo "* running curl in the \"client1\" namespace..."
ip netns exec $clientns1 \
    curl -O https://10.10.10.20/index.html
echo "* running curl in the \"client1\" namespace... done"

echo "* running curl in the \"client2\" namespace..."
ip netns exec $clientns2 \
    curl -O https://10.20.10.20/index.html
echo "* running curl in the \"client2\" namespace... done"

echo "* running wget in the \"client\" namespace..."
ip netns exec $clientns1 \
    wget https://10.10.10.20/index.html
echo "* running wget in the \"client\" namespace... done"

ping_ip=$(echo $serverip1|cut -f1 -d'/')
echo "* running hping3 $ping_ip in the \"client\" namespace..."
set +e
ip netns exec $clientns1 \
    hping3 -c 10 -1 -f -d 15000 $ping_ip
PINGRES=$?
set -e
echo "* running ping in the \"client1\" namespace... done"

# pings should have been dropped, so ping reports error
if [ $PINGRES != 1 ]; then
    echo "ERROR ping should have failed"
    RES=1
fi

ping_ip=$(echo $serverip2|cut -f1 -d'/')
echo "* running ping $ping_ip in the \"client2\" namespace..."
set +e
ip netns exec $clientns2 \
    ping -c 10 $ping_ip
PINGRES=$?
set -e
echo "* running ping in the \"client2\" namespace... done"

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
HPING_DROP_RECS=$(jq -c 'select(.event_type == "drop" and .src_ip == "10.10.10.10")' ./eve.json | wc -l)
PING_DROP_RECS=$(jq -c 'select(.event_type == "drop" and .src_ip == "10.20.10.10")' ./eve.json | wc -l)
echo "ACCEPTED $ACCEPTED BLOCKED $BLOCKED KERNEL_PACKETS $KERNEL_PACKETS"
echo "HPING_DROP_RECS $HPING_DROP_RECS PING_DROP_RECS $PING_DROP_RECS"

if [ $KERNEL_PACKETS -eq 0 ]; then
    echo "ERROR no packets captured"
    RES=1
fi
if [ $ACCEPTED -eq 0 ]; then
    echo "ERROR should have seen non-0 accepted"
    RES=1
fi
if [ $BLOCKED -lt 10 ]; then
    echo "ERROR should have seen 10+ blocked"
    RES=1
fi
if [ $PING_DROP_RECS -lt 10 ]; then
    echo "ERROR should have seen 10+ ping drop logs"
    RES=1
fi
# hping test sets frags and per reassmebled packet we log 2 drop logs currently
if [ $HPING_DROP_RECS -lt 20 ]; then
    echo "ERROR should have seen 20+ hping drop logs"
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
set +e
kill -INT $CADDYPID
kill -INT $CADDYPID2
wait $CADDYPID
CADDYRES=$?
wait $CADDYPID2
CADDYRES2=$?
set -e
ip netns exec $dutns \
    ${SURICATASC} -c "shutdown" /var/run/suricata/suricata-command.socket
wait $SURIPID
echo "* shutting down... done"

# Caddy sometimes exits uncleanly. Warn about it but otherwise
# it can be ignored.
if [ $CADDYRES -ne 0 ] || [ $CADDYRES2 -ne 0 ]; then
    echo "WARNING Caddy exited with error $CADDYRES/$CADDYRES2"
fi

echo "* dumping some stats..."
cat ./eve.json | jq --arg IFACE "bond-$dutclientif1" -c 'select(.tls and .in_iface==$IFACE)'|tail -n1|jq
cat ./eve.json | jq --arg IFACE "bond-$dutclientif2" -c 'select(.tls and .in_iface==$IFACE)'|tail -n1|jq
cat ./eve.json | jq -c 'select(.stats)|.stats.ips'|tail -n1|jq
cat ./eve.json | jq -c 'select(.stats)|.stats.capture'|tail -n1|jq
echo "* dumping some stats... done"

echo "* done: $RES"
exit $RES
