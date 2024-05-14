#!/bin/bash

set -x
#set -e

TD=`dirname "$(readlink -f "$0")"`

SV="$1"
PCAPS="${SV}/tests/"

USOCKET="/var/run/suricata/suricata.socket"
mkdir -p /var/run/suricata/
RULES="${SV}/tests/test-ruleparse-etopen-01/emerging-all.rules"
VERBOSE=""

UnixCommand () {
    COMMAND=$1
    PYTHONPATH=python/ python3 python/bin/suricatasc -c "${COMMAND}" ${USOCKET}
}

Start () {
    src/suricata -c suricata.yaml --unix-socket --set "default-log-dir=." \
                --set "unix-command.filename=$USOCKET" -S ${RULES} \
                --set classification-file=classification.config \
                --set reference-config-file=reference.config -k none &
    SURIPID=$!
    echo "SURIPID $SURIPID"
}

Stop () {
    echo "sending shutdown command"
    UnixCommand shutdown

    echo "waiting for suri $SURIPID to exit"
    wait $SURIPID
    RETVAL=$?
    if [ $RETVAL -ne 0 ]; then
        echo "FAILURE"
        exit 1
    else
        echo "success"
        exit 0
    fi
}

SocketReady() {
    RETVAL=255
    CNT=0

    while [ $RETVAL -ne 0 ]; do
        UnixCommand version
        RETVAL=$?
        sleep 1
        ((CNT++))
        if [ $CNT -eq 300 ]; then
            echo "ERROR: failed to start up"
            exit 1
        fi
    done
}

FeedPcaps() {
    PCAPLIST=$(find ${PCAPS} -type f -name '*.pcap')
    for P in $PCAPLIST; do
        UnixCommand "pcap-file ${P} ."
    done

    # wait for engine to report 0 pcaps in list
    CNT=1
    while [ $CNT -ne 0 ]; do
        RAWCNT=$(UnixCommand pcap-file-number)
        CNT=$(echo $RAWCNT|jq -r 'select(.message)|.message')
	    sleep 3
        echo $CNT
    done
    echo "FeedPcaps: loop done"
    sleep 60
    echo "FeedPcaps: end"
}

Start
SocketReady
FeedPcaps
echo "stopping suri"
Stop
echo "suri stopped"
exit 0
