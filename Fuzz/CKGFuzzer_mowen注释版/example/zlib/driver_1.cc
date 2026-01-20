#include <stdio.h> // Include stdio.h to declare stderr
#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

    // Allocate memory for input and output buffers
    uint8_t* input_buffer = (uint8_t*)safe_malloc(size);
    uint8_t* output_buffer = (uint8_t*)safe_malloc(deflateBound(&strm, size));

    // Copy input data to the input buffer
    safe_memcpy(input_buffer, data, size);

    // Initialize zlib stream
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = input_buffer;
    strm.avail_in = size;
    strm.next_out = output_buffer;
    strm.avail_out = deflateBound(&strm, size);

    // Call inflateResetKeep to reset the inflate state
    int ret = inflateResetKeep(&strm);
    if (ret != Z_OK) {
        free(input_buffer);
        free(output_buffer);
        return 0;
    }

    // Compute Adler-32 checksum
    uLong adler = adler32(0L, Z_NULL, 0);
    adler = adler32(adler, input_buffer, size);

    // Compute CRC-32 checksum
    uLong crc = crc32_z(0L, input_buffer, size);

    // Close the gzFile (simulated close for reading)
    gzFile file = gzopen("dummy_file", "rb"); // Open a dummy file for reading
    if (!file) {
        free(input_buffer);
        free(output_buffer);
        return 0;
    }

    ret = gzclose(file); // Close the dummy file
    if (ret != Z_OK) {
        free(input_buffer);
        free(output_buffer);
        return 0;
    }

    // Free allocated memory
    free(input_buffer);
    free(output_buffer);

    return 0;
}
