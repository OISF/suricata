#!/bin/sh

if [ $1 ]; then
	case $1 in
	*[ch])
		LIST=$@;
		;;
        *..*) 
        	LIST=$(git diff --pretty="format:" --name-only $1 | grep -E '[ch]$')
		PREFIX=$(git rev-parse --show-toplevel)/
		;;
	*)
		LIST=$(git show --pretty="format:" --name-only $1 | grep -E '[ch]$')
		PREFIX=$(git rev-parse --show-toplevel)/
		;;
	esac
else
	LIST=$(git ls-tree -r --name-only --full-tree  HEAD src/ | grep -E '*.c$')
	PREFIX=$(git rev-parse --show-toplevel)/
fi

for SMPL in $(git rev-parse --show-toplevel)/qa/coccinelle/*.cocci; do
	echo "Testing cocci file: $SMPL"
	for FILE in $LIST ; do
		spatch --very-quiet -sp_file $SMPL --undefined UNITTESTS  $PREFIX$FILE || exit 1;
	done
done

exit 0
