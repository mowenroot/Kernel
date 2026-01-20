build_dir=$WORK/build
rm -rf ${build_dir}
mkdir -p ${build_dir}
pushd ${build_dir}

# oss-fuzz has 2 GB total memory allocation limit. So, we limit per-allocation
# limit in libvpx to 1 GB to avoid OOM errors. A smaller per-allocation is
# needed for MemorySanitizer (see bug oss-fuzz:9497 and bug oss-fuzz:9499).
if [[ $CFLAGS = *sanitize=memory* ]]; then
  extra_c_flags='-DVPX_MAX_ALLOCABLE_MEMORY=536870912'
else
  extra_c_flags='-DVPX_MAX_ALLOCABLE_MEMORY=1073741824'
fi

LDFLAGS="$CXXFLAGS" LD=$CXX $SRC/libvpx/configure \
    --enable-vp9-highbitdepth \
    --disable-unit-tests \
    --disable-examples \
    --size-limit=12288x12288 \
    --extra-cflags="${extra_c_flags}" \
    --disable-webm-io \
    --enable-debug \
    # --disable-vp8-encoder \
    # --disable-vp9-encoder
make -j$(nproc) all
popd


fuzzer_decoders=( 'vp9' 'vp8' )
for decoder in "${fuzzer_decoders[@]}"; do
Fuzzer_name=FUZZ_DRIVER_FILE"_"${decoder}
  $CXX $CXXFLAGS -std=c++11 \
      -DDECODER=${decoder} \
      -I$SRC/libvpx \
      -I${build_dir} \
      -Wl,--start-group \
      $LIB_FUZZING_ENGINE \
      $SRC/libvpx/test/FUZZ_DRIVER_FILE -o $OUT/${Fuzzer_name} \
      ${build_dir}/libvpx.a \
      -Wl,--end-group
done
    


