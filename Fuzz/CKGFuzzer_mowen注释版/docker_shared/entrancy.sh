# !/bin/bash
rm /fuzz_driver/a.txt
touch /fuzz_driver/a.txt
echo "COPY DeepSeek" >> /fuzz_driver/a.txt
[ -f $SRC/c-ares/test/ares-test-fuzz.c ] && rm -rf  $SRC/c-ares/test/ares-test-fuzz.c
[ -f $SRC/c-ares/test/ares-test-fuzz-name.c ] && rm -rf $SRC/c-ares/test/ares-test-fuzz-name.c
cp /fuzz_driver/build.sh /src/build.sh
cp -rf /fuzz_driver/fuzz_driver/c-ares/syntax_pass_rag/fix_fuzz_driver_deepseek_2.cpp  $SRC/c-ares/test/ares-test-fuzz.c
cp -rf /fuzz_driver/fuzz_driver/c-ares/syntax_pass_rag/fix_fuzz_driver_deepseek_18.cpp $SRC/c-ares/test/ares-test-fuzz-name.c

cp -rf /fuzz_driver/build.sh $SRC/build.sh
echo "Done Copy DeepSeek" >> /fuzz_driver/a.txt


# cd $SRC
# compile