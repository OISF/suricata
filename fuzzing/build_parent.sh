#!/usr/bin/sh
set -e

cd ..
cp -rfv $(pwd)/src/suricata-common.h $(pwd)/fuzzing/patched_file/suricata-common.h.bkp
cp -rfv $(pwd)/fuzzing/patched_file/suricata-common.h $(pwd)/src/

export CC=clang
export CXX=clang++
export ASAN_OPTIONS=detect_leaks=0

./configure --disable-rust CFLAGS="-O1 -v -g -fPIC -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep -fsanitize=address,undefined,signed-integer-overflow,bool,pointer-overflow" LDFLAG="-fsanitize=address,undefined,signed-integer-overflow,bool,pointer-overflow -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep" 
make -j$(nproc)

cp -rfv $(pwd)/fuzzing/patched_file/suricata-common.h.bkp $(pwd)/src/

cd $(pwd)/src

echo "patch suricata.o ..."
sed -i -e 's/main/mmmm/g' suricata.o
echo "patched ..."

echo "generate archiv suricata_fuzz.a ..."
ar rv suricata_fuzz.a *.o
echo "generated ..."