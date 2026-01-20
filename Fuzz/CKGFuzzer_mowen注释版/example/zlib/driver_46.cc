#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int extractInt(const uint8_t*& data, size_t& size, int min, int max) {
    if (size < sizeof(int)) return min - 1; // Invalid value
    int value = *reinterpret_cast<const int*>(data);
    data += sizeof(int);
    size -= sizeof(int);
    return (value < min || value > max) ? min - 1 : value;
}

// Function to safely extract a byte array from the fuzz input
const uint8_t* extractByteArray(const uint8_t*& data, size_t& size, size_t& extractedSize, size_t maxSize) {
    if (size < sizeof(size_t)) return nullptr; // Invalid size
    extractedSize = *reinterpret_cast<const size_t*>(data);
    data += sizeof(size_t);
    size -= sizeof(size_t);
    if (extractedSize > maxSize || extractedSize > size) return nullptr; // Invalid size or not enough data
    const uint8_t* extractedData = data;
    data += extractedSize;
    size -= extractedSize;
    return extractedData;
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
    int level = extractInt(data, size, 0, 9);
    int strategy = extractInt(data, size, 0, Z_FIXED);
    int bits = extractInt(data, size, 0, 16);
    int value = extractInt(data, size, 0, (1 << bits) - 1);
    size_t dictLength;
    const uint8_t* dictionary = extractByteArray(data, size, dictLength, strm.avail_in);

    // Call deflateParams
    if (level >= 0 && strategy >= 0) {
        ret = deflateParams(&strm, level, strategy);
        if (ret != Z_OK) {
            deflateEnd(&strm);
            return 0;
        }
    }

    // Call deflateSetDictionary
    if (dictionary != nullptr) {
        ret = deflateSetDictionary(&strm, dictionary, dictLength);
        if (ret != Z_OK) {
            deflateEnd(&strm);
            return 0;
        }
    }

    // Call deflatePrime
    if (bits >= 0 && value >= 0) {
        ret = deflatePrime(&strm, bits, value);
        if (ret != Z_OK) {
            deflateEnd(&strm);
            return 0;
        }
    }

    // Call deflateReset
    ret = deflateReset(&strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Clean up
    deflateEnd(&strm);
    return 0;
}
