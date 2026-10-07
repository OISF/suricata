#!/bin/sh
# A chain of files each including the next, one deeper than the include
# limit (MAX_INCLUDE_DEPTH, 128). The last file includes a file that does
# not exist, which is never reached.
cd "$(dirname "$0")"
rm -f ./*.yaml
i=0
while [ $i -le 128 ]; do
    echo "include: $((i + 1)).yaml" > "$i.yaml"
    i=$((i + 1))
done
