#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include stdio.h to use stderr

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

// Function to safely copy memory
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (memcpy(dest, src, n) != dest) {
        fprintf(stderr, "Memory copy failed\n");
        exit(EXIT_FAILURE);
    }
}

// Function to safely set memory
void safe_memset(void* s, int c, size_t n) {
    if (memset(s, c, n) != s) {
        fprintf(stderr, "Memory set failed\n");
        exit(EXIT_FAILURE);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize the zlib stream
    z_stream strm;
    safe_memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    // Initialize deflate
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        return 0;
    }

    // Allocate buffers for input and output
    uint8_t* in_buf = (uint8_t*)safe_malloc(size);
    uint8_t* out_buf = (uint8_t*)safe_malloc(deflateBound(&strm, size));

    // Copy input data to the input buffer
    safe_memcpy(in_buf, data, size);

    // Set up the stream for deflate
    strm.next_in = in_buf;
    strm.avail_in = size;
    strm.next_out = out_buf;
    strm.avail_out = deflateBound(&strm, size);

    // Call deflate to compress the data
    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END && ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Call deflateBound to get the upper bound of the compressed size
    uLong bound = deflateBound(&strm, size);

    // Call deflateParams to adjust compression parameters
    ret = deflateParams(&strm, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Call deflateSetDictionary to set a dictionary for compression
    const uint8_t dictionary[] = "dictionary";
    ret = deflateSetDictionary(&strm, dictionary, sizeof(dictionary) - 1);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Call deflatePrime to insert bits into the stream
    ret = deflatePrime(&strm, 8, 0xFF);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Call deflateCopy to create a copy of the stream
    z_stream strm_copy;
    safe_memset(&strm_copy, 0, sizeof(strm_copy));
    ret = deflateCopy(&strm_copy, &strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        deflateEnd(&strm_copy);
        safe_free(in_buf);
        safe_free(out_buf);
        return 0;
    }

    // Clean up
    deflateEnd(&strm);
    deflateEnd(&strm_copy);
    safe_free(in_buf);
    safe_free(out_buf);

    return 0;
}
