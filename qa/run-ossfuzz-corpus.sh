#/bin/sh
ls src/tests/fuzz/fuzz_*.c | sed 's/\.c//' | while read ftarget
do
    target=$(basename $ftarget)
    echo "target $target"
    #download public corpus
    rm -f public.zip
    wget --quiet "https://storage.googleapis.com/suricata-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/suricata_$target/public.zip"
    rm -rf corpus_$target
    unzip -q public.zip -d corpus_$target
    #run target on corpus. Don't fail CI if the target fails.
    find corpus_$target -type f | xargs -L1 ./src/$target
done
