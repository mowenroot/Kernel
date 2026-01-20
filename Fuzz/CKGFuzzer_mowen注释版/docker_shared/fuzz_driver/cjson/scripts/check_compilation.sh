#!/bin/bash
project=$1
filename=$2
cp -f /generated_fuzzer/fuzz_driver/${project}/${filename}.c /src/${project}/tests/
cd /src/${project}
# [ -d /generated_fuzzer/syntax_check_tmp ] || mkdir -p /generated_fuzzer/syntax_check_tmp
#clang -fsyntax-only -w -Wnote -Wextra -pedantic -Iinclude -Isrc/lib  /src/${project}/test/${filename}
$CC $CFLAGS -w -I/src/${project} -c /src/${project}/tests/${filename}.c  /src/${project}/tests/${filename}
