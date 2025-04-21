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

// Function to safely reallocate memory
void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(ptr);
        exit(1);
    }
    return new_ptr;
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

    // Allocate buffers
    uint8_t* source = (uint8_t*)safe_malloc(size);
    memcpy(source, data, size);

    uint8_t* dest = (uint8_t*)safe_malloc(size);
    uLongf destLen = size;

    // Initialize zlib stream
    int ret = inflateInit(&strm);
    if (ret != Z_OK) {
        free(source);
        free(dest);
        return 0;
    }

    // Call inflatePrime
    ret = inflatePrime(&strm, size % 16, size);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        free(source);
        free(dest);
        return 0;
    }

    // Call gzsetparams
    gzFile file = gzdopen(1, "wb"); // Use stdout as the file descriptor
    if (file == NULL) {
        inflateEnd(&strm);
        free(source);
        free(dest);
        return 0;
    }
    ret = gzsetparams(file, size % 10, size % 4);
    if (ret != Z_OK) {
        gzclose(file);
        inflateEnd(&strm);
        free(source);
        free(dest);
        return 0;
    }
    gzclose(file);

    // Call compress
    ret = compress(dest, &destLen, source, size);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        free(source);
        free(dest);
        return 0;
    }

    // Call deflateSetDictionary
    ret = deflateSetDictionary(&strm, source, size);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        free(source);
        free(dest);
        return 0;
    }

    // Call crc32_z
    unsigned long crc = crc32_z(0L, source, size);
    if (crc == 0) {
        inflateEnd(&strm);
        free(source);
        free(dest);
        return 0;
    }

    // Clean up
    inflateEnd(&strm);
    free(source);
    free(dest);

    return 0;
}
