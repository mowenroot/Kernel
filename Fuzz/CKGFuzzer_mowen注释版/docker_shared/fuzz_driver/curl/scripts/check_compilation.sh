#!/bin/bash
project=$1
filename=$2
cp -f /generated_fuzzer/fuzz_driver/${project}/${filename}.cc /src/${project}/tests/
cd /src/${project}
# [ -d /generated_fuzzer/syntax_check_tmp ] || mkdir -p /generated_fuzzer/syntax_check_tmp
#clang -fsyntax-only -w -Wnote -Wextra -pedantic -Iinclude -Isrc/lib  /src/${project}/test/${filename}
$CXX $CXXFLAGS -w -I/src/${project}/include/ -c /src/${project}/tests/${filename}.cc -o /src/${project}/tests/${filename}.o
