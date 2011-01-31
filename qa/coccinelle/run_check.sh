#!/bin/sh

for SMPL in *.cocci; do
	echo "Testing cocci file: $SMPL"
	for FILE in $(git ls-tree -r --name-only --full-tree  HEAD src/ | grep -E '*.c$') ; do
		spatch -sp_file $SMPL  ../../$FILE 2>/dev/null || exit 1;
	done
done

exit 0
