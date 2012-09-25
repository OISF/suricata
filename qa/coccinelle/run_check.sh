#!/bin/sh

if [ $1 ]; then
	LIST=$1;
else
	LIST=$(git ls-tree -r --name-only --full-tree  HEAD src/ | grep -E '*.c$')
	PREFIX="../../"
fi

for SMPL in *.cocci; do
	echo "Testing cocci file: $SMPL"
	for FILE in $LIST ; do
		spatch -sp_file $SMPL --undefined UNITTESTS  $PREFIX$FILE 2>/dev/null || exit 1;
	done
done

exit 0
