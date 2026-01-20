#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a buffer
uint8_t* safe_alloc(size_t size) {
    if (size == 0) return nullptr;
    uint8_t* buf = (uint8_t*)malloc(size);
    if (!buf) return nullptr;
    return buf;
}

// Function to safely free allocated memory
void safe_free(void* ptr) {
    if (ptr) free(ptr);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 10) return 0;

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) return 0;

    // Extract parameters from fuzz input
    int level = data[0];
    int strategy = data[1];
    int bits = data[2];
    int value = data[3];
    size_t dictLength = data[4];
    const uint8_t* dictionary = data + 5;

    // Ensure dictionary length does not exceed available data
    if (dictLength > size - 5) dictLength = size - 5;

    // Call deflateParams
    ret = deflateParams(&strm, level, strategy);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Call deflateSetDictionary
    ret = deflateSetDictionary(&strm, dictionary, dictLength);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Call deflatePrime
    ret = deflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Create a copy of the stream for deflateCopy
    z_stream strm_copy;
    memset(&strm_copy, 0, sizeof(strm_copy));
    ret = deflateCopy(&strm_copy, &strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        deflateEnd(&strm_copy);
        return 0;
    }

    // Call deflateBound
    uLong bound = deflateBound(&strm, size);
    if (bound == 0) {
        deflateEnd(&strm);
        deflateEnd(&strm_copy);
        return 0;
    }

    // Allocate output buffer for deflateBound
    uint8_t* out_buf = safe_alloc(bound);
    if (!out_buf) {
        deflateEnd(&strm);
        deflateEnd(&strm_copy);
        return 0;
    }

    // Set up output buffer for deflate
    strm.next_out = out_buf;
    strm.avail_out = bound;

    // Call deflate
    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        safe_free(out_buf);
        deflateEnd(&strm);
        deflateEnd(&strm_copy);
        return 0;
    }

    // Call deflateReset
    ret = deflateReset(&strm);
    if (ret != Z_OK) {
        safe_free(out_buf);
        deflateEnd(&strm);
        deflateEnd(&strm_copy);
        return 0;
    }

    // Clean up
    safe_free(out_buf);
    deflateEnd(&strm);
    deflateEnd(&strm_copy);

    return 0;
}
