#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include this header to declare stderr

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
    unsigned int pending = 0;
    int bits = 0;
    unsigned long crc = 0;
    int ret;

    // Allocate memory for input and output buffers
    uint8_t* input_buffer = (uint8_t*)safe_malloc(size);
    uint8_t* output_buffer = (uint8_t*)safe_malloc(deflateBound(&strm, size));

    // Copy input data to the input buffer
    safe_memcpy(input_buffer, data, size);

    // Initialize the zlib stream for deflate
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        safe_free(input_buffer);
        safe_free(output_buffer);
        return 0;
    }

    // Set the input and output buffers
    strm.next_in = input_buffer;
    strm.avail_in = size;
    strm.next_out = output_buffer;
    strm.avail_out = deflateBound(&strm, size);

    // Perform deflate compression
    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(input_buffer);
        safe_free(output_buffer);
        return 0;
    }

    // Check deflate pending
    ret = deflatePending(&strm, &pending, &bits);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(input_buffer);
        safe_free(output_buffer);
        return 0;
    }

    // Calculate CRC32
    crc = crc32_z(crc, output_buffer, strm.total_out);

    // End deflate
    deflateEnd(&strm);

    // Initialize the zlib stream for inflate
    memset(&strm, 0, sizeof(strm));
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        safe_free(input_buffer);
        safe_free(output_buffer);
        return 0;
    }

    // Set the input and output buffers for inflate
    strm.next_in = output_buffer;
    strm.avail_in = strm.total_out;
    strm.next_out = input_buffer;
    strm.avail_out = size;

    // Perform inflate decompression
    ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        inflateEnd(&strm);
        safe_free(input_buffer);
        safe_free(output_buffer);
        return 0;
    }

    // Prime the inflate stream
    ret = inflatePrime(&strm, bits, pending);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        safe_free(input_buffer);
        safe_free(output_buffer);
        return 0;
    }

    // End inflate
    inflateEnd(&strm);

    // Free allocated memory
    safe_free(input_buffer);
    safe_free(output_buffer);

    return 0;
}
