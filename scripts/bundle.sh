#! /usr/bin/env bash

while IFS= read -r requirement; do
    set -- $requirement
    case "$1" in
        suricata-update)
            echo "===> Fetching $1"
            (cd suricata-update &&
                 curl -Ls "$2" | tar zxf - --strip-components=1)
            ;;
        libhtp)
            echo "===> Fetching $1"
            mkdir -p libhtp
            (cd libhtp &&
                 curl -Ls "$2" | tar zxf - --strip-components=1)
            ;;
        *)
            echo "error: unknown requirement: $1"
            ;;
    esac
done < ./requirements.txt
