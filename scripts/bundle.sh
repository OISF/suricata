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
#   SU_BRANCH: Override the Suricata-Update branch to a branch, tag or
#              {pull,merge}-request.
#
#   LIBHTP_REPO:   Overrides the libhtp git repo
#   LIBHTP_BRANCH: Override the libhtp branch to a branch, tag or
#                  {pull,merge}-request.
#
#   DESTDIR: Checkout to another directory instead of the current
#            directory.
#
# To specify a pull or merge request in a branch name in the format of
# pr/NNN or mr/NNN.

set -e

DESTDIR=${DESTDIR:-.}

what="$1"

# Transforms a branch name in the form of "pr/<NUMBER>" or
# "mr/<NUMBER>" into a proper ref for GitHub or Gitlab.
transform_branch() {
    pr=$(echo "${1}" | sed -n 's/^pr\/\([[:digit:]]\+\)$/\1/p')
    if [ "${pr}" ]; then
        echo "refs/pull/${pr}/head"
        return
    fi

    mr=$(echo "${1}" | sed -n 's/^mr\/\([[:digit:]]\+\)$/\1/p')
    if [ "${mr}" ]; then
        echo "refs/merge-requests/${mr}/head"
        return
    fi

    echo "${1}"
}

fetch() {
    repo="$1"
    dest="$2"
    branch="$3"

    git clone --depth 1 "${repo}" "${dest}"
    pushd "${dest}"
    git fetch origin "${branch}"
    git -c advice.detachedHead=false checkout FETCH_HEAD
    popd
}

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
            SU_BRANCH=$(transform_branch ${SU_BRANCH:-$3})
            echo "===> Bundling ${SU_REPO} (${SU_BRANCH})"
            rm -rf ${DESTDIR}/suricata-update.tmp
            fetch "${SU_REPO}" "${DESTDIR}/suricata-update.tmp" "${SU_BRANCH}"
            rm -rf ${DESTDIR}/suricata-update.tmp/.git
            cp -a ${DESTDIR}/suricata-update.tmp/. ${DESTDIR}/suricata-update
            rm -rf ${DESTDIR}/suricata-update.tmp
            ;;
        libhtp)
            LIBHTP_REPO=${LIBHTP_REPO:-$2}
            LIBHTP_BRANCH=$(transform_branch ${LIBHTP_BRANCH:-$3})
            echo "===> Bundling ${LIBHTP_REPO} (${LIBHTP_BRANCH})"
            rm -rf ${DESTDIR}/libhtp
            fetch "${LIBHTP_REPO}" "${DESTDIR}/libhtp" "${LIBHTP_BRANCH}"
            rm -rf libhtp/.git
            ;;
        \#*)
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
