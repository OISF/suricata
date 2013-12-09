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

if [ -z "$CONCURRENCY_LEVEL" ]; then
	CONCURRENCY_LEVEL=1
	echo "No concurrency"
else
	echo "Using concurrency level $CONCURRENCY_LEVEL"
fi

for SMPL in $(git rev-parse --show-toplevel)/qa/coccinelle/*.cocci; do
	echo "Testing cocci file: $SMPL"
	if command -v parallel >/dev/null; then
		echo -n $LIST | parallel -d ' ' -j $CONCURRENCY_LEVEL spatch --very-quiet -sp_file $SMPL --undefined UNITTESTS $PREFIX{} || if [ -z "$NOT_TERMINAL" ]; then exit 1; fi
	else
		for FILE in $LIST ; do
			spatch --very-quiet -sp_file $SMPL --undefined UNITTESTS  $PREFIX$FILE || if [ -z "$NOT_TERMINAL" ]; then exit 1; fi
		done
	fi
done

exit 0
