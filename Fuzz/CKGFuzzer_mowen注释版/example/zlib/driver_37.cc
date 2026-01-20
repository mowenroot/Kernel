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

    // Allocate memory for the dictionary
    uint8_t* dictionary = (uint8_t*)safe_malloc(size);
    safe_memcpy(dictionary, data, size);

    // Call inflatePrime
    int inflatePrimeResult = inflatePrime(&strm, size % 16, *(int*)data);
    if (inflatePrimeResult != Z_OK) {
        free(dictionary);
        return 0;
    }

    // Call compressBound
    uLong compressBoundResult = compressBound(size);
    if (compressBoundResult < size) {
        free(dictionary);
        return 0;
    }

    // Call gzdopen (note: gzdopen requires a valid file descriptor, which is not available in fuzzing context)
    // We simulate the behavior by checking the mode string
    const char* mode = "rb";
    gzFile gzFileHandle = gzdopen(-1, mode);
    if (gzFileHandle == NULL) {
        free(dictionary);
        return 0;
    }

    // Call deflateSetDictionary
    int deflateSetDictionaryResult = deflateSetDictionary(&strm, dictionary, size);
    if (deflateSetDictionaryResult != Z_OK) {
        free(dictionary);
        return 0;
    }

    // Call crc32_z
    unsigned long crc32Result = crc32_z(0L, data, size);
    if (crc32Result == 0) {
        free(dictionary);
        return 0;
    }

    // Free allocated resources
    free(dictionary);

    return 0;
}
