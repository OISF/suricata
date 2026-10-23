#!/bin/sh
# Redmine #8777: live local-VALE netmap fragment coalescing regression.
# Not a Suricata-Verify test; it needs /dev/netmap and root on FreeBSD.
set -eu
umask 077

if [ "$#" -ne 1 ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage (as root): $0 /absolute/path/to/built/suricata" >&2
    exit 2
fi
source_dir=$(CDPATH= cd -- "$1" && pwd)
case_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
base=$(mktemp -d "${TMPDIR:-/tmp}/netmap-8777.XXXXXX")
suri_pid=
stop_suri()
{
    if [ -n "$suri_pid" ] && kill -0 "$suri_pid" 2>/dev/null; then
        kill -INT "$suri_pid" || true
        wait "$suri_pid" || true
    fi
    suri_pid=
}
cleanup()
{
    stop_suri
    if [ "${NETMAP_8777_KEEP_RESULTS:-0}" = 1 ]; then
        echo "Redmine #8777 results kept in $base"
    else
        rm -rf "$base"
    fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

"$source_dir/src/suricata" --build-info | grep -q 'Netmap support:.*yes'
cc -O2 -Wall -Wextra -Werror -o "$base/sender" "$case_dir/send-zero-fragment.c" -lnetmap
printf '%s\n' 'alert udp any any -> any any (msg:"NETMAP_8777_TAIL_MARKER"; content:"NETMAP_8777_TAIL_MARKER"; sid:8777001; rev:1;)' > "$base/rules"

for mode in control zero-fragment; do
    out="$base/$mode"
    mkdir "$out"
    "$source_dir/src/suricata" --netmap=vale0:suri --runmode=workers \
        -c "$source_dir/suricata.yaml" -S "$base/rules" -l "$out" \
        --set outputs.3.pcap-log.enabled=yes \
        --set outputs.3.pcap-log.filename=output.pcap \
        --set outputs.3.pcap-log.conditional=all \
        >"$out/stdout.log" 2>&1 &
    suri_pid=$!
    # Wait for receive threads to initialize and attach before sending.
    startup_wait=60
    while :; do
        if ! kill -0 "$suri_pid" 2>/dev/null; then
            echo "Suricata did not start for $mode" >&2
            tail -40 "$out/stdout.log" >&2
            exit 2
        fi
        if [ -f "$out/stdout.log" ] && grep -Fq 'Engine started.' "$out/stdout.log"; then
            break
        fi
        if [ "$startup_wait" -eq 0 ]; then
            echo "Timed out waiting for Suricata to start for $mode" >&2
            tail -40 "$out/stdout.log" >&2
            exit 2
        fi
        sleep 1
        startup_wait=$((startup_wait - 1))
    done
    "$base/sender" vale0:sender "$mode" "$out/expected.bin"
    sleep 2
    if ! kill -0 "$suri_pid" 2>/dev/null; then
        echo "Suricata exited during $mode" >&2
        tail -40 "$out/stdout.log" >&2
        exit 2
    fi
    stop_suri
    python3 "$case_dir/verify.py" "$mode" "$out"
done
