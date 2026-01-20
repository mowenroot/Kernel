#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from source to destination with bounds checking
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (dest == nullptr || src == nullptr || n == 0) return;
    memcpy(dest, src, n);
}

// Function to safely convert a byte array to an integer with bounds checking
int safe_byte_to_int(const uint8_t* data, size_t size, size_t offset, size_t length) {
    if (offset + length > size) return 0;
    int result = 0;
    for (size_t i = 0; i < length; ++i) {
        result = (result << 8) | data[offset + i];
    }
    return result;
}

// Function to safely convert a byte array to an unsigned integer with bounds checking
unsigned int safe_byte_to_uint(const uint8_t* data, size_t size, size_t offset, size_t length) {
    if (offset + length > size) return 0;
    unsigned int result = 0;
    for (size_t i = 0; i < length; ++i) {
        result = (result << 8) | data[offset + i];
    }
    return result;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize deflate
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Extract parameters from fuzz input
    int level = safe_byte_to_int(data, size, 0, 1);
    int strategy = safe_byte_to_int(data, size, 1, 1);
    int bits = safe_byte_to_int(data, size, 2, 1);
    int value = safe_byte_to_int(data, size, 3, 1);
    unsigned int sourceLen = safe_byte_to_uint(data, size, 4, 4);

    // Call deflateParams
    ret = deflateParams(&strm, level, strategy);
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

    // Call deflateBound
    uLong bound = deflateBound(&strm, sourceLen);
    if (bound == 0) {
        deflateEnd(&strm);
        return 0;
    }

    // Allocate memory for dictionary
    Bytef* dictionary = (Bytef*)malloc(bound);
    if (dictionary == nullptr) {
        deflateEnd(&strm);
        return 0;
    }

    // Call deflateGetDictionary
    uInt dictLength = 0;
    ret = deflateGetDictionary(&strm, dictionary, &dictLength);
    if (ret != Z_OK) {
        free(dictionary);
        deflateEnd(&strm);
        return 0;
    }

    // Call deflatePending
    unsigned pending = 0;
    int pendingBits = 0;
    ret = deflatePending(&strm, &pending, &pendingBits);
    if (ret != Z_OK) {
        free(dictionary);
        deflateEnd(&strm);
        return 0;
    }

    // Call deflateCopy
    z_stream strmCopy;
    memset(&strmCopy, 0, sizeof(strmCopy));
    ret = deflateCopy(&strmCopy, &strm);
    if (ret != Z_OK) {
        free(dictionary);
        deflateEnd(&strm);
        deflateEnd(&strmCopy);
        return 0;
    }

    // Clean up
    free(dictionary);
    deflateEnd(&strm);
    deflateEnd(&strmCopy);

    return 0;
}
