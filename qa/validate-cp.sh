#!/bin/bash

#set -x
#set -e

if [ $# -ne 1 ]; then
    echo "call with base branch (e.g. main-7.0.x)"
    exit 1;
fi

BASE=$1

if [ -z "${CHECK_BRANCHES}" ]; then
    CHECK_BRANCHES="remotes/origin/main remotes/origin/main-8.0.x"
fi

test_cherrypicked_line() {
    REV=$1
    #echo "\"REV $REV\""

    CHERRY=$(echo $REV | grep '(cherry picked from commit' | awk '{print $5}'|awk -F')' '{print $1}' || return 1)

    for branch in ${CHECK_BRANCHES}; do
        if git branch -a --contains ${CHERRY} | grep " ${branch}" &> /dev/null; then
            echo -n "OK "
            return
        fi
    done

    echo -n "ERROR $CHERRY not found in $CHECK_BRANCH"
    return 1
}

for rev in $(git rev-list --reverse origin/${BASE}..HEAD); do
    echo -n "COMMIT $rev: "

    GREPOP=$(git log --format=%B -n 1 $rev | grep 'cherry picked from commit')
    if [ ! -z "$GREPOP" ]; then
        while IFS= read -r line; do
            test_cherrypicked_line "$line" || exit 1
        done <<< "$GREPOP"
        echo
    else
        echo "not a cherry-pick"
    fi
done
