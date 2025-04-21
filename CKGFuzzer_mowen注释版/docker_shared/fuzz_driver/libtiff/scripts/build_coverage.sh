pushd "$SRC/zlib"
./configure --static --prefix="$WORK"
make -j$(nproc) CFLAGS="$CFLAGS -fPIC"
make install
popd

# Build libjpeg-turbo
pushd "$SRC/libjpeg-turbo"
cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DENABLE_STATIC=on -DENABLE_SHARED=off
make -j$(nproc)
make install
popd

# Build libjbig
pushd "$SRC/jbigkit"
make lib
mv "$SRC"/jbigkit/libjbig/*.a "$WORK/lib/"
mv "$SRC"/jbigkit/libjbig/*.h "$WORK/include/"
popd

if [ "$ARCHITECTURE" != "i386" ]; then
    apt-get install -y liblzma-dev
fi


cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DBUILD_SHARED_LIBS=off
make -j$(nproc)
make install

$CXX $CXXFLAGS -std=c++11 -I$WORK/include \
    $SRC/libtiff/test/FUZZ_DRIVER_FILE -o $OUT/FUZZ_DRIVER_FILE_TARGET\
    -lFuzzingEngine $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a $WORK/lib/libz.a $WORK/lib/libjpeg.a \
    $WORK/lib/libjbig.a $WORK/lib/libjbig85.a -llzma