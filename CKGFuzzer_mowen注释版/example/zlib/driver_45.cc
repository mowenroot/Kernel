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

// Function to safely extract a string from the fuzz input
const char* extractString(const uint8_t* data, size_t size, size_t& offset, size_t maxLen) {
    if (offset + maxLen > size) {
        return nullptr; // Not enough data
    }
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += maxLen;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the z_stream structure
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize the deflate stream
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
    const char* dictionary = extractString(data, size, offset, 1024); // Assume max dictionary size of 1024 bytes
    uInt dictLength = dictionary ? strlen(dictionary) : 0;

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

    // Call deflateSetDictionary
    if (dictionary) {
        ret = deflateSetDictionary(&strm, reinterpret_cast<const Bytef*>(dictionary), dictLength);
        if (ret != Z_OK) {
            deflateEnd(&strm);
            return 0; // Early exit on error
        }
    }

    // Call deflateBound
    uLong sourceLen = size;
    uLong bound = deflateBound(&strm, sourceLen);
    if (bound == 0) {
        deflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Allocate output buffer for deflateCopy
    z_stream strmCopy;
    memset(&strmCopy, 0, sizeof(strmCopy));
    ret = deflateCopy(&strmCopy, &strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        deflateEnd(&strmCopy);
        return 0; // Early exit on error
    }

    // Clean up
    deflateEnd(&strm);
    deflateEnd(&strmCopy);

    return 0; // Success
}
