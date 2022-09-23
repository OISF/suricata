#! /usr/bin/env bash
#
# This script will bundle libhtp and/or suricata-update for you.
#
# To use, run from the top Suricata source directory:
#
#    ./scripts/bundle.sh [suricata-update|libhtp]
#
# If no arguments are provided, both suricata-update and libhtp will
# be bundled.
#
# Environment variables:
#
#   SU_REPO:   Overrides the Suricata-Update git repo
#   SU_BRANCH: Override the Suricata-Update branch
#   SU_PR:     Use a GitHub pull-request from SU_REPO
#
#   LIBHTP_REPO:   Overrides the libhtp git repo
#   LIBHTP_BRANCH: Override the libhtp branch
#   LIBHTP_PR:     Use a GitHub pull-request from LIBHTP_REPO

set -e

what="$1"

while IFS= read -r requirement; do
    set -- $requirement

    # If a requirement was specified on the command line, skip all other
    # requirements.
    if [ "${what}" != "" ]; then
        if [ "${what}" != "$1" ]; then
            continue
        fi
    fi
    case "$1" in
        suricata-update)
            SU_REPO=${SU_REPO:-$2}
            SU_BRANCH=${SU_BRANCH:-$3}
            echo "===> Bundling ${SU_REPO} -b ${SU_BRANCH}"
            rm -rf suricata-update.tmp
            git clone --depth 1 "${SU_REPO}" -b "${SU_BRANCH}" suricata-update.tmp
            if [[ "${SU_PR}" != "" ]]; then
                echo "---> Switching to pull requrest ${SU_PR}"
                cd suricata-update.tmp
                git fetch origin pull/${SU_PR}/head:pr
                git checkout pr
                cd ..
            fi
            cp -a suricata-update.tmp/* suricata-update/
            rm -rf suricata-update.tmp
            ;;
        libhtp)
            LIBHTP_REPO=${LIBHTP_REPO:-$2}
            LIBHTP_BRANCH=${LIBHTP_BRANCH:-$3}
            echo "===> Bundling ${LIBHTP_REPO} -b ${LIBHTP_BRANCH}"
            rm -rf libhtp
            git clone "${LIBHTP_REPO}" -b "${LIBHTP_BRANCH}" libhtp
            if [[ "${LIBHTP_PR}" != "" ]]; then
                echo "---> Switching to pull requrest ${LIBHTP_PR}"
                cd libhtp
                git fetch origin pull/${SU_PR}/head:pr
                git checkout pr
                cd ..
            fi
            rm -rf libhtp/.git
            ;;
        \#)
            # Ignore comment.
            ;;
        "")
            # Ignore blank line.
            ;;
        *)
            echo "error: unknown requirement: $1"
            ;;
    esac
done < ./requirements.txt
