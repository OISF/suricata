#!/bin/sh

if [ $1 ]; then
	case $1 in
	*[ch])
		LIST=$@;
		;;
        *..*) 
        	LIST=$(git diff --pretty="format:" --name-only $1 | grep -E '[ch]$')
		PREFIX="../../"
		;;
	*)
		LIST=$(git show --pretty="format:" --name-only $1 | grep -E '[ch]$')
		PREFIX="../../"
		;;
	esac
else
	LIST=$(git ls-tree -r --name-only --full-tree  HEAD src/ | grep -E '*.c$')
	PREFIX="../../"
fi

for SMPL in *.cocci; do
	echo "Testing cocci file: $SMPL"
	for FILE in $LIST ; do
		spatch --very-quiet -sp_file $SMPL $PREFIX$FILE || exit 1;
	done
done

exit 0
