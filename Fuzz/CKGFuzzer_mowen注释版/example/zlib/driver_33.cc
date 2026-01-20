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
    // Ensure the input size is sufficient for our operations
    if (size < 10) {
        return 0;
    }

    // Initialize variables
    gzFile gz_file = gzopen("dummy_file", "wb");  // Open a dummy file for gzFile operations
    z_streamp z_stream = (z_streamp)safe_malloc(sizeof(z_stream));
    unsigned long crc = 0;
    int ret;

    // Initialize z_stream
    memset(z_stream, 0, sizeof(z_stream));

    // Extract parameters from fuzz input
    int c = data[0];
    int bits = data[1];
    int value = data[2];
    int level = data[3];
    int strategy = data[4];
    size_t dict_len = data[5];
    const uint8_t* dict = data + 6;

    // Call gzungetc
    ret = gzungetc(c, gz_file);
    if (ret < 0) {
        safe_free(z_stream);
        gzclose(gz_file);  // Close the dummy file
        return 0;
    }

    // Call inflatePrime
    ret = inflatePrime(z_stream, bits, value);
    if (ret != Z_OK) {
        safe_free(z_stream);
        gzclose(gz_file);  // Close the dummy file
        return 0;
    }

    // Call gzsetparams
    ret = gzsetparams(gz_file, level, strategy);
    if (ret != Z_OK) {
        safe_free(z_stream);
        gzclose(gz_file);  // Close the dummy file
        return 0;
    }

    // Call deflateSetDictionary
    ret = deflateSetDictionary(z_stream, dict, dict_len);
    if (ret != Z_OK) {
        safe_free(z_stream);
        gzclose(gz_file);  // Close the dummy file
        return 0;
    }

    // Call crc32_z
    crc = crc32_z(crc, data, size);

    // Clean up
    safe_free(z_stream);
    gzclose(gz_file);  // Close the dummy file

    return 0;
}
