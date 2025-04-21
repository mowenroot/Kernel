#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int extractInt(const uint8_t* data, size_t size, size_t& offset, int min, int max) {
    if (offset + sizeof(int) > size) {
        return min; // Default to minimum value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return (value < min || value > max) ? min : value;
}

// Function to safely extract a size_t from the fuzz input
size_t extractSizeT(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(size_t) > size) {
        return 0; // Default to 0 if not enough data
    }
    size_t value = *reinterpret_cast<const size_t*>(data + offset);
    offset += sizeof(size_t);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize deflate
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        return 0; // Early exit on error
    }

    // Extract parameters from fuzz input
    size_t offset = 0;
    int level = extractInt(data, size, offset, 0, 9);
    int strategy = extractInt(data, size, offset, 0, Z_FIXED);
    int bits = extractInt(data, size, offset, 0, 16);
    int value = extractInt(data, size, offset, 0, (1 << bits) - 1);
    int good_length = extractInt(data, size, offset, 0, 32);
    int max_lazy = extractInt(data, size, offset, 0, 258);
    int nice_length = extractInt(data, size, offset, 0, 258);
    int max_chain = extractInt(data, size, offset, 0, 4096);
    size_t sourceLen = extractSizeT(data, size, offset);

    // Call deflateParams
    ret = deflateParams(&strm, level, strategy);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Call deflatePrime
    ret = deflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Call deflateTune
    ret = deflateTune(&strm, good_length, max_lazy, nice_length, max_chain);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Call deflateBound
    uLong bound = deflateBound(&strm, sourceLen);
    if (bound == 0) {
        deflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Allocate output buffer
    uint8_t* outbuf = (uint8_t*)malloc(bound);
    if (!outbuf) {
        deflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Prepare for deflate
    strm.next_out = outbuf;
    strm.avail_out = bound;

    // Call deflateCopy
    z_stream strm_copy;
    memset(&strm_copy, 0, sizeof(strm_copy));
    ret = deflateCopy(&strm_copy, &strm);
    if (ret != Z_OK) {
        free(outbuf);
        deflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Call deflateReset
    ret = deflateReset(&strm);
    if (ret != Z_OK) {
        free(outbuf);
        deflateEnd(&strm);
        deflateEnd(&strm_copy);
        return 0; // Early exit on error
    }

    // Clean up
    free(outbuf);
    deflateEnd(&strm);
    deflateEnd(&strm_copy);

    return 0; // Return 0 to indicate success
}
