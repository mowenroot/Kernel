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
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    gzFile gz = nullptr;
    uLong crc = 0;
    int ret = 0;

    // Allocate memory for the dictionary
    const size_t dict_size = size / 2;
    if (dict_size > 0) {
        Bytef* dict = (Bytef*)safe_malloc(dict_size);
        safe_memcpy(dict, data, dict_size);

        // Call deflateSetDictionary
        ret = deflateSetDictionary(&strm, dict, dict_size);
        if (ret != Z_OK) {
            free(dict);
            return 0;
        }

        // Free the dictionary memory
        free(dict);
    }

    // Call inflatePrime
    int bits = (data[0] % 17) + 1; // Random number of bits between 1 and 17
    int value = (data[1] % (1 << bits)); // Random value within the bit range
    ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        return 0;
    }

    // Call crc32_z
    crc = crc32_z(crc, data, size);

    // Call crc32_combine_gen
    uLong len2 = size;
    uLong crc_gen = crc32_combine_gen(len2);

    // Call gzdopen
    int fd = 1; // Dummy file descriptor
    const char* mode = "rb"; // Read-only mode
    gz = gzdopen(fd, mode);
    if (!gz) {
        return 0;
    }

    // Clean up resources
    if (gz) {
        gzclose(gz);
    }

    return 0;
}
