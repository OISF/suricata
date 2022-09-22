#/bin/sh
ls src/fuzz_* | while read ftarget
do
    target=$(basename $ftarget)
    echo "target $target"
    #download public corpus
    rm -f public.zip
    wget --quiet "https://storage.googleapis.com/suricata-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/suricata_$target/public.zip"
    rm -rf corpus_$target
    unzip -q public.zip -d corpus_$target
    #run target on corpus.
    export LLVM_PROFILE_FILE="/tmp/$target.profraw"
    /usr/bin/time -v ./src/$target corpus_$target
done
