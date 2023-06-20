r=0
cat qa/rustfmt.txt | while read i; do
    rustfmt $i;
    if [ $(git diff -- $i | wc -l) -gt 0 ]; then
        git diff;
        echo "$i" needs to be formatted
        r=1;
    fi
done
exit $r
