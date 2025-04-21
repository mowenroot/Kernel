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



cd libpcap
# build project
mkdir -p build
cd build
cmake ..
make

$CXX $CXXFLAGS  -I/src/libpcap -c $SRC/libpcap/tests/FUZZ_DRIVER_FILE -o $WORK/FUZZ_DRIVER_FILE_TARGET.o
$CXX $CXXFLAGS  -std=c++11 $WORK/FUZZ_DRIVER_FILE_TARGET.o \
    -o $OUT/FUZZ_DRIVER_FILE_TARGET \
    $LIB_FUZZING_ENGINE libpcap.a
