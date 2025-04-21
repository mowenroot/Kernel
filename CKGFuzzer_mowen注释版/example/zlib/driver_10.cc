#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include for stderr and stdout

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
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize deflate state
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        return 0;
    }

    // Reset deflate state
    ret = deflateReset(&strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Set dictionary for deflate
    if (size >= 32) {
        ret = deflateSetDictionary(&strm, data, 32);
        if (ret != Z_OK) {
            deflateEnd(&strm);
            return 0;
        }
    }

    // Initialize inflate state
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Prime inflate state with bits from input
    if (size >= 4) {
        int bits = data[0];
        int value = (data[1] << 8) | data[2];
        ret = inflatePrime(&strm, bits, value);
        if (ret != Z_OK) {
            inflateEnd(&strm);
            deflateEnd(&strm);
            return 0;
        }
    }

    // Set compression parameters for gzFile
    gzFile file = gzdopen(fileno(stdout), "wb");
    if (file == NULL) {
        inflateEnd(&strm);
        deflateEnd(&strm);
        return 0;
    }

    int level = data[0] % 10; // Compression level (0-9)
    int strategy = data[1] % 4; // Compression strategy (0-3)
    ret = gzsetparams(file, level, strategy);
    if (ret != Z_OK) {
        gzclose(file);
        inflateEnd(&strm);
        deflateEnd(&strm);
        return 0;
    }

    // Compute CRC32 checksum
    unsigned long crc = crc32_z(0L, NULL, 0);
    crc = crc32_z(crc, data, size);

    // Clean up
    gzclose(file);
    inflateEnd(&strm);
    deflateEnd(&strm);

    return 0;
}
