How to run fuzzing ?

1) With oss-fuzz
- install docker
- run git clone --depth 1 https://github.com/google/oss-fuzz
- change directory into cloned repository : cd oss-fuzz
- run python infra/helper.py build_image suricata
- run python infra/helper.py build_fuzzers --sanitizer address suricata
You can use undefined sanitizer
- run python infra/helper.py run_fuzzer suricata fuzz_siginit
(or another fuzz target, try ls build/out/suricata/fuzz_*)

To generate coverage :
- run python infra/helper.py build_fuzzers --sanitizer=coverage suricata
- get a corpus cf https://github.com/google/oss-fuzz/issues/2490
- put your corpus in build/corpus/suricata/<fuzz_target_name>/
- run python infra/helper.py coverage --no-corpus-download suricata

2) With libfuzzer

To compile the fuzz targets, you can do the following.
These flags are just one option and you are welcome to change them when you know what you are doing.
```
export CFLAGS="-g -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
export CXXFLAGS="-g -O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -stdlib=libc++"
export RUSTFLAGS="--cfg fuzzing -Cdebuginfo=1 -Cforce-frame-pointers"
export RUSTFLAGS="$RUSTFLAGS -Cpasses=sancov -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-trace-geps -Cllvm-args=-sanitizer-coverage-prune-blocks=0 -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth"
export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
export CC=clang
export CXX=clang++
./configure --enable-fuzztargets
make
```

You can specify other sanitizers here such as undefined and memory

Then you can run a target :
./src/.libs/fuzz_target_x your_libfuzzer_options
Where target_x is on file in `ls ./src/.libs/fuzz_*`

If your clang does not support the compile flag "-fsanitize=fuzzer" (MacOS), you can run these same commands but you need first to install libfuzzer as libFuzzingEngine and you need to add `export LIB_FUZZING_ENGINE=/path/to/libFuzzer.a` before calling configure command

To compile libFuzzer, you can do the following
```
svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer
cd fuzzer
./build.sh
```


3) With afl

To compile the fuzz targets, you simply need to run
```
CC=afl-gcc ./configure --enable-fuzztargets
CC=afl-gcc make
```
You can rather use afl-clang if needed.

Then you can run afl as usual with each of the fuzz targets in ./src/.libs/
afl-fuzz your_afl_options -- ./src/.libs/fuzz_target_x @@
