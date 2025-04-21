#include <stdio.h>  // Include stdio.h to use stderr
#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize deflate state
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        return 0;
    }

    // Allocate buffers for input and output
    Bytef* in_buf = (Bytef*)safe_malloc(size);
    Bytef* out_buf = (Bytef*)safe_malloc(deflateBound(&strm, size));

    // Copy input data to the input buffer
    memcpy(in_buf, data, size);

    // Set input and output buffers
    strm.next_in = in_buf;
    strm.avail_in = size;
    strm.next_out = out_buf;
    strm.avail_out = deflateBound(&strm, size);

    // Set dictionary if input size is sufficient
    if (size > 32) {
        ret = deflateSetDictionary(&strm, in_buf, 32);
        if (ret != Z_OK) {
            deflateEnd(&strm);
            safe_free(in_buf);
            safe_free(out_buf);
            return 0;
        }
    }

    // Perform deflate compression
    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Compute Adler-32 checksum of the compressed data
    uLong adler = adler32_z(0L, out_buf, strm.total_out);

    // Reset the deflate state with a new window size
    ret = inflateReset2(&strm, 15);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Clean up
    deflateEnd(&strm);
    safe_free(in_buf);
    safe_free(out_buf);

    return 0;
}
