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

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < 1 || size > 1024 * 1024) {
        return 0;
    }

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize variables for API parameters
    int bits = data[0] % 17; // Valid range for bits is 0 to 16
    int value = (data[1] << 8) | data[2]; // 16-bit value
    int level = data[3] % 10; // Valid range for level is 0 to 9
    int strategy = data[4] % 4; // Valid range for strategy is 0 to 3
    uInt dictLength = data[5]; // Length of dictionary

    // Allocate memory for dictionary
    const Bytef* dictionary = (const Bytef*)safe_malloc(dictLength);
    memcpy((void*)dictionary, data + 6, dictLength);

    // Call inflatePrime
    int ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        safe_free((void*)dictionary);
        return 0;
    }

    // Call gzsetparams
    gzFile file = (gzFile)&strm; // Simulate gzFile with z_stream
    ret = gzsetparams(file, level, strategy);
    if (ret != Z_OK) {
        safe_free((void*)dictionary);
        return 0;
    }

    // Call deflateSetDictionary
    ret = deflateSetDictionary(&strm, dictionary, dictLength);
    if (ret != Z_OK) {
        safe_free((void*)dictionary);
        return 0;
    }

    // Call crc32_z
    unsigned long crc = crc32_z(0L, data, size);
    if (crc == 0) {
        safe_free((void*)dictionary);
        return 0;
    }

    // Call deflateBound
    uLong bound = deflateBound(&strm, size);
    if (bound == 0) {
        safe_free((void*)dictionary);
        return 0;
    }

    // Free allocated resources
    safe_free((void*)dictionary);

    return 0;
}
