#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int safe_extract_int(const uint8_t *data, size_t size, size_t &offset, int min, int max) {
    if (offset + sizeof(int) > size) {
        return min; // Default to minimum value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return (value < min || value > max) ? min : value;
}

// Function to safely extract a string from the fuzz input
const uint8_t* safe_extract_string(const uint8_t *data, size_t size, size_t &offset, size_t max_len, size_t &str_len) {
    if (offset >= size) {
        return nullptr;
    }
    str_len = size - offset;
    if (str_len > max_len) {
        str_len = max_len;
    }
    const uint8_t* str = data + offset;
    offset += str_len;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    size_t offset = 0;

    // Extract parameters from fuzz input
    int bits = safe_extract_int(data, size, offset, 0, 16);
    int value = safe_extract_int(data, size, offset, 0, (1 << bits) - 1);
    int level = safe_extract_int(data, size, offset, 0, 9);
    int strategy = safe_extract_int(data, size, offset, 0, Z_FIXED);
    size_t dict_len;
    const uint8_t* dictionary = safe_extract_string(data, size, offset, 32768, dict_len);

    // Initialize zlib stream
    int ret = inflateInit(&strm);
    if (ret != Z_OK) {
        return 0;
    }

    // Call inflatePrime
    ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Call deflateParams
    ret = deflateParams(&strm, level, strategy);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0;
    }

    // Call deflateSetDictionary
    if (dictionary) {
        ret = deflateSetDictionary(&strm, dictionary, dict_len);
        if (ret != Z_OK) {
            inflateEnd(&strm);
            return 0;
        }
    }

    // Call crc32_z
    unsigned long crc = crc32_z(0L, data, size);

    // Clean up
    inflateEnd(&strm);
    return 0;
}
