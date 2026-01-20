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

// Function to safely allocate memory for a dictionary
uint8_t* safe_dict_alloc(size_t size) {
    if (size == 0) return nullptr;
    uint8_t* dict = (uint8_t*)malloc(size);
    if (!dict) return nullptr;
    return dict;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    int ret;

    // Extract dictionary size and mode from fuzz input
    size_t dict_size = data[0];
    const char* mode = safe_strndup(data + 1, 3); // Assume mode is 3 characters long
    if (!mode) return 0;

    // Allocate dictionary buffer
    uint8_t* dictionary = safe_dict_alloc(dict_size);
    if (!dictionary) {
        free((void*)mode);
        return 0;
    }

    // Initialize deflate stream
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        free((void*)mode);
        free(dictionary);
        return 0;
    }

    // Set dictionary
    ret = deflateSetDictionary(&strm, data + 4, dict_size);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        free((void*)mode);
        free(dictionary);
        return 0;
    }

    // Get dictionary
    uInt dictLength = 0;
    ret = deflateGetDictionary(&strm, dictionary, &dictLength);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        free((void*)mode);
        free(dictionary);
        return 0;
    }

    // Reset inflate stream
    ret = inflateReset(&strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        free((void*)mode);
        free(dictionary);
        return 0;
    }

    // Open gz file
    int fd = 1; // Dummy file descriptor
    gzFile gz = gzdopen(fd, mode);
    if (!gz) {
        deflateEnd(&strm);
        free((void*)mode);
        free(dictionary);
        return 0;
    }

    // Compute CRC32
    unsigned long crc = crc32_z(0L, data + 4, dict_size);

    // Clean up
    deflateEnd(&strm);
    free((void*)mode);
    free(dictionary);
    gzclose(gz);

    return 0;
}
