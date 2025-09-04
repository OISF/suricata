#!/bin/bash -eu

date

cd $SRC/
# build dependencies statically
if [ "$SANITIZER" = "memory" ]
then
    (
    cd zlib
    ./configure --static
    make -j$(nproc) clean
    make -j$(nproc) all
    make -j$(nproc) install
    )
fi

(
tar -xvzf pcre2-10.44.tar.gz
cd pcre2-10.44
./configure --disable-shared
make -j$(nproc) clean
make -j$(nproc) all
make -j$(nproc) install
)

tar -xvzf lz4-1.10.0.tar.gz
cd lz4-1.10.0
make liblz4.a
cp lib/liblz4.a /usr/local/lib/
cp lib/lz4*.h /usr/local/include/
cd ..

tar -xvzf jansson-2.14.tar.gz
cd jansson-2.14
./configure --disable-shared
make -j$(nproc)
make install
cd ..

tar -xvzf libpcap-1.10.5.tar.gz
cd libpcap-1.10.5
./configure --disable-shared
make -j$(nproc)
make install
cd ..

cd fuzzpcap
mkdir build
cd build
cmake ..
make install
cd ../..

cd libyaml
./bootstrap
./configure --disable-shared
make -j$(nproc)
make install
cd ..

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
# cf https://github.com/google/sanitizers/issues/1389
export MSAN_OPTIONS=strict_memcmp=false

#run configure with right options
if [ "$SANITIZER" = "address" ]
then
    export RUSTFLAGS="$RUSTFLAGS -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth -Ccodegen-units=1"
    export RUSTFLAGS="$RUSTFLAGS -Cdebug-assertions=yes"
fi

date

rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

# build project

date

cd suricata
sh autogen.sh

./src/tests/fuzz/oss-fuzz-configure.sh
make -j$(nproc)

date

./src/suricata --list-app-layer-protos | tail -n +2 | while read i; do cp src/fuzz_applayerparserparse $OUT/fuzz_applayerparserparse""_$i; done

(
cd src
ls fuzz_* | while read i; do
    cp $i $OUT/$i
    # download oss-fuzz public corpuses
    wget "https://storage.googleapis.com/suricata-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/suricata_$i/public.zip" --output-file=$OUT/"$i"_seed_corpus.zip || true
done
)

date

# dictionaries
./src/suricata --list-keywords | grep "\- " | sed 's/- //' | awk '{print "\""$0"\""}' > $OUT/fuzz_siginit.dict

echo \"SMB\" > $OUT/fuzz_applayerparserparse""_smb.dict

echo "\"FPC0\"" > $OUT/fuzz_sigpcap_aware.dict
echo "\"FPC0\"" > $OUT/fuzz_predefpcap_aware.dict

git grep tag rust | grep '"' | cut -d '"' -f2 | sort | uniq | awk 'length($0) > 2' | awk '{print "\""$0"\""}' | grep -v '\\' > generic.dict
cat generic.dict >> $OUT/fuzz_siginit.dict
cat generic.dict >> $OUT/fuzz_applayerparserparse.dict
cat generic.dict >> $OUT/fuzz_sigpcap.dict
cat generic.dict >> $OUT/fuzz_sigpcap_aware.dict

date
