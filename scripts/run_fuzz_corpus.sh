#/bin/sh

ls src/fuzz_* | sed 's/src\///' | while read target
do
    #download public corpus
    wget "https://storage.googleapis.com/suricata-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/suricata_$target/public.zip"
    unzip -q public.zip -d corpus_$target
    #run target on corpus
    echo "Running $target"
    ./src/$target corpus_$target
done
