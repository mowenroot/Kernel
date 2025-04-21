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

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD
SCRIPTDIR=${BUILD_ROOT}/scripts

. ${SCRIPTDIR}/fuzz_targets

ZLIBDIR=/src/zlib
OPENSSLDIR=/src/openssl
NGHTTPDIR=/src/nghttp2
GDBDIR=/src/gdb

# Check for GDB-specific behaviour by checking for the GDBMODE flag.
# - Compile with -O0 so that DEBUGASSERTs can be debugged in gdb.
if [[ -n ${GDBMODE:-} ]]
then
  export CFLAGS="$CFLAGS -O0"
  export CXXFLAGS="$CXXFLAGS -O0"
fi

echo "BUILD_ROOT: $BUILD_ROOT"
echo "SRC: ${SRC:-undefined}"
echo "CC: $CC"
echo "CXX: $CXX"
echo "LIB_FUZZING_ENGINE: $LIB_FUZZING_ENGINE"
echo "CFLAGS: $CFLAGS"
echo "CXXFLAGS: $CXXFLAGS"
echo "ARCHITECTURE: $ARCHITECTURE"
echo "FUZZ_TARGETS: $FUZZ_TARGETS"

export MAKEFLAGS+="-j$(nproc)"

# Make an install directory
export INSTALLDIR=/src/curl_install

# Check for GDB-specific behaviour by checking for the GDBMODE flag.
# - Compile and installing GDB if necessary.
if [[ -n ${GDBMODE:-} ]]
then
  if ! type gdb 2>/dev/null
  then
    # If gdb isn't found, then download and install GDB.
    # This installs to the default configure location.
    ${SCRIPTDIR}/handle_x.sh gdb ${GDBDIR} system || exit 1
  fi
fi

# Install zlib
${SCRIPTDIR}/handle_x.sh zlib ${ZLIBDIR} ${INSTALLDIR} || exit 1

# For the memory sanitizer build, turn off OpenSSL as it causes bugs we can't
# affect (see 16697, 17624)
if [[ ${SANITIZER} != "memory" ]]
then
    # Install openssl
    export OPENSSLFLAGS="-fno-sanitize=alignment"
    ${SCRIPTDIR}/handle_x.sh openssl ${OPENSSLDIR} ${INSTALLDIR} || exit 1
fi

# Install nghttp2
${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTPDIR} ${INSTALLDIR} || exit 1

# Compile curl
${SCRIPTDIR}/install_curl.sh /src/curl ${INSTALLDIR}


$CXX $CXXFLAGS -std=c++11 -I/src/curl/include/ \
    -c /src/curl/tests/FUZZ_DRIVER_FILE  -o FUZZ_DRIVER_FILE_TARGET.o

$CXX $CXXFLAGS -std=c++11 FUZZ_DRIVER_FILE_TARGET.o \
    -o $OUT/FUZZ_DRIVER_FILE_TARGET \
    $LIB_FUZZING_ENGINE ${INSTALLDIR}/lib/libcurl.a \
    ${INSTALLDIR}/lib/libssl.a ${INSTALLDIR}/lib/libcrypto.a \
    ${INSTALLDIR}/lib/libz.a ${INSTALLDIR}/lib/libnghttp2.a

