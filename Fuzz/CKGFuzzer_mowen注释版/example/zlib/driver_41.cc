#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include for stderr

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely copy memory
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within reasonable limits to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize variables
    uLong crc1 = 0;
    uLong crc2 = 0;
    z_off_t len2 = 0;
    int bits = 0;
    int value = 0;
    uInt dictLength = 0;
    z_streamp strm = nullptr;
    Bytef* dictionary = nullptr;

    // Allocate memory for the stream structure
    strm = (z_streamp)safe_malloc(sizeof(z_stream));
    memset(strm, 0, sizeof(z_stream));

    // Allocate memory for the dictionary
    dictionary = (Bytef*)safe_malloc(size);
    safe_memcpy(dictionary, data, size);

    // Derive inputs from fuzz data
    if (size >= sizeof(uLong) * 2 + sizeof(z_off_t) + sizeof(int) * 2 + sizeof(uInt)) {
        crc1 = *(uLong*)(data);
        crc2 = *(uLong*)(data + sizeof(uLong));
        len2 = *(z_off_t*)(data + sizeof(uLong) * 2);
        bits = *(int*)(data + sizeof(uLong) * 2 + sizeof(z_off_t));
        value = *(int*)(data + sizeof(uLong) * 2 + sizeof(z_off_t) + sizeof(int));
        dictLength = *(uInt*)(data + sizeof(uLong) * 2 + sizeof(z_off_t) + sizeof(int) * 2);
    }

    // Call crc32_combine
    uLong combined_crc = crc32_combine(crc1, crc2, len2);

    // Call inflatePrime
    int inflate_result = inflatePrime(strm, bits, value);
    if (inflate_result != Z_OK) {
        free(strm);
        free(dictionary);
        return 0;
    }

    // Call crc32
    uLong crc = crc32(0L, dictionary, dictLength);

    // Call deflateSetDictionary
    int deflate_result = deflateSetDictionary(strm, dictionary, dictLength);
    if (deflate_result != Z_OK) {
        free(strm);
        free(dictionary);
        return 0;
    }

    // Call crc32_z
    uLong crc_z = crc32_z(0L, dictionary, dictLength);

    // Free allocated resources
    free(strm);
    free(dictionary);

    return 0;
}
