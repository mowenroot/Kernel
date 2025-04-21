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

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
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
    int ret;

    // Allocate memory for the dictionary
    uint8_t* dictionary = (uint8_t*)safe_malloc(size);
    safe_memcpy(dictionary, data, size);

    // Initialize the stream for deflate
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        free(dictionary);
        return 0;
    }

    // Set the dictionary for deflate
    ret = deflateSetDictionary(&strm, dictionary, size);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        free(dictionary);
        return 0;
    }

    // Initialize the stream for inflate
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        free(dictionary);
        return 0;
    }

    // Prime the inflate state with bits from the input data
    int bits = (size > 16) ? 16 : size;
    ret = inflatePrime(&strm, bits, *((int*)data));
    if (ret != Z_OK) {
        inflateEnd(&strm);
        deflateEnd(&strm);
        free(dictionary);
        return 0;
    }

    // Compute the CRC-32 checksum of the input data
    unsigned long crc = crc32_z(0L, data, size);

    // Open a gzFile handle using a dummy file descriptor and mode
    gzFile gz = gzdopen(1, "wb");
    if (!gz) {
        inflateEnd(&strm);
        deflateEnd(&strm);
        free(dictionary);
        return 0;
    }

    // Close the gzFile handle
    gzclose(gz);

    // Clean up
    inflateEnd(&strm);
    deflateEnd(&strm);
    free(dictionary);

    return 0;
}
