#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include for stderr and tmpfile

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
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

    // Initialize variables
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Allocate buffers
    Bytef* dictionary = (Bytef*)safe_malloc(size);
    uInt dictLength = size;
    int bits = (int)(data[0] % 17); // Random number of bits (0-16)
    int value = (int)(data[1] % 256); // Random value (0-255)
    int level = (int)(data[2] % 10); // Compression level (0-9)
    int strategy = (int)(data[3] % 4); // Compression strategy (0-3)

    // Initialize CRC
    unsigned long crc = crc32_z(0L, Z_NULL, 0);

    // Call crc32_z to compute CRC of the input data
    crc = crc32_z(crc, data, size);

    // Call deflateSetDictionary
    int ret = deflateSetDictionary(&strm, data, size);
    if (ret != Z_OK) {
        free(dictionary);
        return 0;
    }

    // Call deflateGetDictionary
    ret = deflateGetDictionary(&strm, dictionary, &dictLength);
    if (ret != Z_OK) {
        free(dictionary);
        return 0;
    }

    // Call inflatePrime
    ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        free(dictionary);
        return 0;
    }

    // Call gzsetparams
    FILE* tempFile = tmpfile();  // Create a temporary file
    if (!tempFile) {
        free(dictionary);
        return 0;
    }
    gzFile file = gzdopen(fileno(tempFile), "wb");
    if (file == Z_NULL) {
        free(dictionary);
        return 0;
    }
    ret = gzsetparams(file, level, strategy);
    if (ret != Z_OK) {
        gzclose(file);
        free(dictionary);
        return 0;
    }
    gzclose(file);

    // Free allocated resources
    free(dictionary);

    return 0;
}
