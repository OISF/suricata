#!/bin/bash

NAME=$1

SERIES=$(ls ${NAME}/dump/ |sort|cut -f 1 -d'.'|sort -u)

for S in $SERIES; do
    FILEPATH="${NAME}/dump/${S}.999"
    if [ ! -f $FILEPATH ]; then
        echo "SERIE $S incomplete, possible crash"
    fi
done

