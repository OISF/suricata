#! /bin/sh

r=0
# check the list of known rustfmt-ed files
cat qa/rustfmt.txt | while read i; do
    cargo fmt $i;
    # the file used to be formatted and is not anymore
    if [ $(git diff -- $i | wc -l) -gt 0 ]; then
        git diff;
        echo "$i" needs to be formatted
	# do not bail early to print all the incorrect files
        r=1;
    fi
done
exit $r
