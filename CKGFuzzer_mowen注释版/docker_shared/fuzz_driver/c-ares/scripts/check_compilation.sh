#!/bin/bash
set -x 
project=$1
filename=$2
cp -f /generated_fuzzer/fuzz_driver/${project}/${filename}.cc /src/${project}/test/
cd /src/${project}
# [ -d /generated_fuzzer/syntax_check_tmp ] || mkdir -p /generated_fuzzer/syntax_check_tmp
#clang -fsyntax-only -w -Wnote -Wextra -pedantic -Iinclude -Isrc/lib  /src/${project}/test/${filename}
$CC $CFLAGS -w -Iinclude -Isrc/lib -c /src/${project}/test/${filename}.cc -o /src/${project}/test/${filename}.o
