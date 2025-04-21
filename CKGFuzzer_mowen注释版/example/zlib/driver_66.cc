#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to handle input data
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the z_stream structure
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Allocate memory for the inflate state
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = const_cast<uint8_t*>(data);
    strm.avail_in = size;

    // Initialize the inflate state
    int ret = inflateInit2(&strm, -MAX_WBITS);
    if (ret != Z_OK) {
        return ret;
    }

    // Buffer for output data
    const size_t out_buf_size = 1024;
    uint8_t out_buf[out_buf_size];
    strm.next_out = out_buf;
    strm.avail_out = out_buf_size;

    // Perform inflate operations
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END) {
        inflateEnd(&strm);
        return ret;
    }

    // Reset the inflate state
    ret = inflateReset(&strm);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return ret;
    }

    // Reset the inflate state with a different window size
    ret = inflateReset2(&strm, MAX_WBITS);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return ret;
    }

    // Reset the inflate state while keeping the dictionary
    ret = inflateResetKeep(&strm);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return ret;
    }

    // Clean up and deallocate resources
    ret = inflateEnd(&strm);
    if (ret != Z_OK) {
        return ret;
    }

    return 0;
}
