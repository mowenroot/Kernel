#include <stdio.h>  // Include for stderr and stdout
#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Allocate memory for the dictionary
    uint8_t* dictionary = (uint8_t*)safe_malloc(size);
    memcpy(dictionary, data, size);

    // Initialize variables for API parameters
    int windowBits = 15; // Default window size
    int wrap = 1; // Default wrap mode
    int level = Z_DEFAULT_COMPRESSION; // Default compression level
    int strategy = Z_DEFAULT_STRATEGY; // Default compression strategy
    int bits = 8; // Default number of bits
    int value = 0xFF; // Default value

    // Call inflateReset2
    int ret = inflateReset2(&strm, windowBits);
    if (ret != Z_OK) {
        safe_free(dictionary);
        return 0;
    }

    // Call deflatePrime
    ret = deflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        safe_free(dictionary);
        return 0;
    }

    // Call gzsetparams
    gzFile file = gzdopen(fileno(stdout), "wb"); // Dummy file for demonstration
    if (file) {
        ret = gzsetparams(file, level, strategy);
        if (ret != Z_OK) {
            gzclose(file);
            safe_free(dictionary);
            return 0;
        }
        gzclose(file);
    }

    // Call deflateSetDictionary
    ret = deflateSetDictionary(&strm, dictionary, size);
    if (ret != Z_OK) {
        safe_free(dictionary);
        return 0;
    }

    // Call crc32_z
    unsigned long crc = crc32_z(0L, data, size);
    (void)crc; // Suppress unused variable warning

    // Free allocated memory
    safe_free(dictionary);

    return 0;
}
