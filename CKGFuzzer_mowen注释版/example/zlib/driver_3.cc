#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
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

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Allocate input and output buffers
    uint8_t* in_buf = (uint8_t*)safe_malloc(size);
    uint8_t* out_buf = (uint8_t*)safe_malloc(size);

    // Copy input data to in_buf
    safe_memcpy(in_buf, data, size);

    // Initialize deflate
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Set input and output buffers
    strm.next_in = in_buf;
    strm.avail_in = size;
    strm.next_out = out_buf;
    strm.avail_out = size;

    // Perform deflate
    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Get the compressed size
    size_t compressed_size = size - strm.avail_out;

    // Initialize inflate
    z_stream inf_strm;
    memset(&inf_strm, 0, sizeof(inf_strm));

    ret = inflateInit(&inf_strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Set input and output buffers for inflate
    inf_strm.next_in = out_buf;
    inf_strm.avail_in = compressed_size;
    inf_strm.next_out = in_buf;
    inf_strm.avail_out = size;

    // Perform inflate
    ret = inflate(&inf_strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        inflateEnd(&inf_strm);
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Calculate CRC32 for the original data
    uLong crc_original = crc32_z(0L, data, size);

    // Calculate CRC32 for the decompressed data
    uLong crc_decompressed = crc32_z(0L, in_buf, size - inf_strm.avail_out);

    // Compare CRC32 values
    if (crc_original != crc_decompressed) {
        fprintf(stderr, "CRC32 mismatch: original=%lx, decompressed=%lx\n", crc_original, crc_decompressed);
    }

    // Clean up
    inflateEnd(&inf_strm);
    deflateEnd(&strm);
    safe_free(in_buf);
    safe_free(out_buf);

    return 0;
}
