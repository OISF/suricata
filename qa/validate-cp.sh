#!/bin/bash

#set -x
#set -e

if [ $# -ne 1 ]; then
    echo "call with base branch (e.g. master-5.0.x)"
    exit 1;
fi

BASE=$1
CHECK_BRANCH="${VALIDATE_CHECK_BRANCH:-remotes/origin/master}"

test_cherrypicked_line() {
    REV=$1
    #echo "\"REV $REV\""

    CHERRY=$(echo $REV | grep '(cherry picked from commit' | awk '{print $5}'|awk -F')' '{print $1}' || return 1)
    git branch -a --contains $CHERRY | grep " $CHECK_BRANCH$" &> /dev/null
    if [ "$?" -ne 0 ]; then
        echo -n "ERROR $CHERRY not found in $CHECK_BRANCH"
        return 1
    else
        echo -n "OK "
    fi
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
