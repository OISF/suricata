#!/bin/bash

set -e
set -x

while getopts ":c:p:r:a:h" option; do
    case $option in
        h)
            echo "$0 -c <suricata yaml> -p <pcap file> -r <rule file> -a <mpm algo(s)>"
            echo
            echo "Example:"
            echo "$0 -c suricata.yaml -p /path/to/pcapfile -r /path/to/rulefile -a \"hs ac ac-ks\""
            echo
            echo "Run from your Suricata directory, with Suricata compiled with --enable-profiling"
            exit 0
            ;;
        a)
            ALGOS="$OPTARG"
            ;;
        c)
            YAML=$OPTARG
            ;;
        p)
            PCAP=$OPTARG
            ;;
        r)
            RULES=$OPTARG
            ;;
   esac
done
YAML=${YAML:-"suricata.yaml"}

if [ ! -f src/suricata ]; then
    echo "ERROR src/suricata not found"
    exit 1
fi
HAS_PROFILING=$(src/suricata --build-info|grep PROFILING|wc -l)
if [ $HAS_PROFILING -ne 1]; then
    echo "ERROR suricata should be built with --enable-profiling"
    exit 1
fi

if [ -z $ALGOS ] || [ -z $PCAP ] || [ -z $RULES ]; then
    echo "ERROR need -a -p and -r"
    exit 1
fi

for A in $ALGOS; do
    for P in $PCAP; do
        for R in $RULES; do
            PCAP_BASE=$(basename $P)
            RULE_BASE=$(basename $R)
            DIRBASE="profile-mpm-$PCAP_BASE-$RULE_BASE"
            DIRNAME="$DIRBASE-$A"   
            mkdir -p $DIRNAME
            src/suricata -c $YAML -r $P -S $R --set mpm-algo=$A -l $DIRNAME --runmode=single -v --set profiling.packets.append=no --set profiling.prefilter.append=no
        done
    done
done

grep -E "DETECT_PF_PAYLOAD.*\s6\s " profile-mpm-*/packet_stats.log
