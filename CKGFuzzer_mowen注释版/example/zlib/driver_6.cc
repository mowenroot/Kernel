#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include for stderr and stdout

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr == nullptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr != nullptr) {
        free(ptr);
    }
}

// Function to safely copy memory
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (dest == nullptr || src == nullptr) {
        fprintf(stderr, "Invalid memory addresses for memcpy\n");
        exit(EXIT_FAILURE);
    }
    memcpy(dest, src, n);
}

// Function to safely set memory
void safe_memset(void* s, int c, size_t n) {
    if (s == nullptr) {
        fprintf(stderr, "Invalid memory address for memset\n");
        exit(EXIT_FAILURE);
    }
    memset(s, c, n);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize zlib stream structures
    z_stream stream1, stream2;
    safe_memset(&stream1, 0, sizeof(z_stream));
    safe_memset(&stream2, 0, sizeof(z_stream));

    // Initialize deflate state
    int ret = deflateInit(&stream1, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        return 0;
    }

    // Copy deflate state
    ret = deflateCopy(&stream2, &stream1);
    if (ret != Z_OK) {
        deflateEnd(&stream1);
        return 0;
    }

    // Set dictionary for deflate
    ret = deflateSetDictionary(&stream1, data, size);
    if (ret != Z_OK) {
        deflateEnd(&stream1);
        deflateEnd(&stream2);
        return 0;
    }

    // Prime inflate state
    ret = inflatePrime(&stream2, 8, 0xFF);
    if (ret != Z_OK) {
        deflateEnd(&stream1);
        deflateEnd(&stream2);
        return 0;
    }

    // Adjust compression parameters
    gzFile file = gzdopen(fileno(stdout), "wb");
    if (file == nullptr) {
        deflateEnd(&stream1);
        deflateEnd(&stream2);
        return 0;
    }
    ret = gzsetparams(file, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        gzclose(file);
        deflateEnd(&stream1);
        deflateEnd(&stream2);
        return 0;
    }
    gzclose(file);

    // Compute CRC32
    unsigned long crc = crc32_z(0L, nullptr, 0);
    crc = crc32_z(crc, data, size);

    // Clean up
    deflateEnd(&stream1);
    deflateEnd(&stream2);

    return 0;
}
