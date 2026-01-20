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

    // Initialize variables
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Allocate memory for the dictionary
    uint8_t* dictionary = (uint8_t*)safe_malloc(size);
    memcpy(dictionary, data, size);

    // Initialize the stream for deflate
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        safe_free(dictionary);
        return 0;
    }

    // Call deflateSetDictionary
    ret = deflateSetDictionary(&strm, dictionary, size);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(dictionary);
        return 0;
    }

    // Call inflatePrime
    ret = inflatePrime(&strm, size % 16, size);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(dictionary);
        return 0;
    }

    // Call gzsetparams
    gzFile file = (gzFile)&strm; // Simulate gzFile using z_stream
    ret = gzsetparams(file, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(dictionary);
        return 0;
    }

    // Call crc32_z
    unsigned long crc = crc32_z(0L, data, size);
    (void)crc; // Suppress unused variable warning

    // Clean up
    deflateEnd(&strm);
    safe_free(dictionary);

    return 0;
}
