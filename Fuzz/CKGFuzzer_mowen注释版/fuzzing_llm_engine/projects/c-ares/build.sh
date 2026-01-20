#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Build the project.
# 运行 buildconf 脚本，准备构建环境
./buildconf

# 配置项目，启用调试模式并禁用测试
./configure --enable-debug --disable-tests

# 清理之前的构建结果
make clean

# 使用所有可用的 CPU 核心进行并行编译，并输出详细的构建信息
make -j$(nproc) V=1 all

# Build the fuzzers.
# 使用 C 编译器编译模糊测试源文件 ares-test-fuzz.c，生成目标文件
$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/c-ares/test/ares-test-fuzz.c -o $WORK/ares-test-fuzz.o

# 使用 C++ 编译器将目标文件链接成可执行的模糊测试程序
$CXX $CXXFLAGS -std=c++11 $WORK/ares-test-fuzz.o \
    -o $OUT/ares_parse_reply_fuzzer \  # 输出文件路径和名称
    $LIB_FUZZING_ENGINE \              # 链接模糊测试引擎库
    $SRC/c-ares/src/lib/.libs/libcares.a  # 链接 c-ares 库

# 同样地，编译另一个模糊测试源文件 ares-test-fuzz-name.c
$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/c-ares/test/ares-test-fuzz-name.c \
    -o $WORK/ares-test-fuzz-name.o

# 将第二个模糊测试程序链接成可执行文件
$CXX $CXXFLAGS -std=c++11 $WORK/ares-test-fuzz-name.o \
    -o $OUT/ares_create_query_fuzzer \  # 输出文件路径和名称
    $LIB_FUZZING_ENGINE \               # 链接模糊测试引擎库
    $SRC/c-ares/src/lib/.libs/libcares.a  # 链接 c-ares 库

# Archive and copy to $OUT seed corpus if the build succeeded.
# 如果构建成功，将种子语料库打包并复制到输出目录
zip -j $OUT/ares_parse_reply_fuzzer_seed_corpus.zip $SRC/c-ares/test/fuzzinput/*  # 打包第一个模糊测试程序的种子语料库

# 打包第二个模糊测试程序的种子语料库
zip -j $OUT/ares_create_query_fuzzer_seed_corpus.zip \
    $SRC/c-ares/test/fuzznames/*