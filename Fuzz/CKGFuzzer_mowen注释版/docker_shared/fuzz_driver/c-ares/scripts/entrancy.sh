# !/bin/bash

# This is for debugging
# rm /fuzz_driver/a.txt
# touch /fuzz_driver/a.txt
# echo "COPY DeepSeek" >> /fuzz_driver/a.txt
# [ -f $SRC/c-ares/test/ares-test-fuzz.c ] && rm -rf  $SRC/c-ares/test/ares-test-fuzz.c
# [ -f $SRC/c-ares/test/ares-test-fuzz-name.c ] && rm -rf $SRC/c-ares/test/ares-test-fuzz-name.c

# Function to remove the suffix of a file name
remove_suffix() {
  local filename="$1"
  local basename="${filename%.*}"
  echo "$basename"
}
set -x 
# Read the command line arguments
fuzz_driver_file=$1
project_name=$2

# Get the base name without the suffix
fuzz_driver_base=$(remove_suffix "$fuzz_driver_file")

# Copy the build script
cp /generated_fuzzer/fuzz_driver/${project_name}/scripts/build.sh $SRC/build.sh

# Copy the fuzz driver file
echo "cp -rf /generated_fuzzer/fuzz_driver/${project_name}/compilation_pass_rag/${fuzz_driver_file} $SRC/${project_name}/test/${fuzz_driver_file}" #>> /generated_fuzzer/fuzz_driver/${project_name}/scripts/a.txt
cp -rf /generated_fuzzer/fuzz_driver/${project_name}/compilation_pass_rag/${fuzz_driver_file} $SRC/${project_name}/test/${fuzz_driver_file}

# Replace placeholders in the build script
sed -i "s/FUZZ_DRIVER_FILE_TARGET/$fuzz_driver_base/g" $SRC/build.sh
sed -i "s/FUZZ_DRIVER_FILE/$fuzz_driver_file/g" $SRC/build.sh

# Optionally, print the modified build.sh for debugging
# cat $SRC/build.sh
# cd $SRC/${project_name} 
#compile
