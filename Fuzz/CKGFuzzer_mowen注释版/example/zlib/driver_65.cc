#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to handle input data
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Initialize the z_stream structure
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Allocate memory for the inflate state
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    // Initialize the inflate state
    int ret = inflateInit2(&strm, -MAX_WBITS);
    if (ret != Z_OK) {
        return 0;
    }

    // Set up the input data
    strm.next_in = const_cast<uint8_t*>(data);
    strm.avail_in = size;

    // Allocate a buffer for the output data
    const size_t output_buffer_size = 1024;
    std::unique_ptr<uint8_t[]> output_buffer(new uint8_t[output_buffer_size]);
    strm.next_out = output_buffer.get();
    strm.avail_out = output_buffer_size;

    // Call inflatePrime to initialize the bit buffer
    ret = inflatePrime(&strm, 16, 0xFFFF);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Call inflateReset to reset the inflate state
    ret = inflateReset(&strm);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Call inflateBack to decompress the data
    ret = inflateBack(&strm, nullptr, nullptr, nullptr, nullptr);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Call inflateReset2 to reset the inflate state with a specified window size
    ret = inflateReset2(&strm, MAX_WBITS);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Call inflateBackEnd to clean up and deallocate resources
    ret = inflateBackEnd(&strm);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // End the inflate process
    inflateEnd(&strm);

    return 0;
}
