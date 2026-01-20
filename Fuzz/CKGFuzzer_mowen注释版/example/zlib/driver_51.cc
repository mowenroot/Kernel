#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a dictionary
uint8_t* safe_dict_alloc(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    uint8_t* dict = (uint8_t*)malloc(size);
    if (!dict) return nullptr;
    memcpy(dict, data, size);
    return dict;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    // Initialize deflate
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Extract parameters from fuzz input
    int level = data[0];
    int strategy = data[1];
    int bits = data[2];
    int value = data[3];
    size_t dictLength = data[4];
    const uint8_t* dictData = data + 5;

    // Ensure dictionary length is within bounds
    if (dictLength > size - 5) {
        dictLength = size - 5;
    }

    // Allocate and set dictionary
    std::unique_ptr<uint8_t[]> dict(safe_dict_alloc(dictData, dictLength));
    if (dict) {
        ret = deflateSetDictionary(&strm, dict.get(), dictLength);
        if (ret != Z_OK) {
            deflateEnd(&strm);
            return 0;
        }
    }

    // Adjust compression parameters
    ret = deflateParams(&strm, level, strategy);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Insert prime bits
    ret = deflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Calculate bound
    uLong bound = deflateBound(&strm, size);
    if (bound == 0) {
        deflateEnd(&strm);
        return 0;
    }

    // Reset deflate state
    ret = deflateReset(&strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Clean up
    deflateEnd(&strm);
    return 0;
}
