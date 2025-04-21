#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include for stderr

// Function to safely copy data from source to destination with size checking
void safe_memcpy(void* dest, const void* src, size_t dest_size, size_t src_size) {
    if (src_size > dest_size) {
        src_size = dest_size;
    }
    memcpy(dest, src, src_size);
}

// Function to safely allocate memory and handle errors
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 16) {
        return 0;
    }

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize gz_header
    gz_header header;
    memset(&header, 0, sizeof(header));

    // Extract parameters from fuzz input
    int bits = data[0];
    int value = data[1];
    int level = data[2];
    int strategy = data[3];
    uLong len2 = (uLong)data[4] | ((uLong)data[5] << 8);
    uInt dictLength = (uInt)data[6] | ((uInt)data[7] << 8);

    // Ensure dictionary length does not exceed input size
    if (dictLength > size - 8) {
        dictLength = size - 8;
    }

    // Allocate memory for dictionary
    Bytef* dictionary = (Bytef*)safe_malloc(dictLength);
    safe_memcpy(dictionary, data + 8, dictLength, dictLength);

    // Initialize zlib stream
    int ret;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        free(dictionary);
        return 0;
    }

    // Call inflatePrime
    ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        free(dictionary);
        return 0;
    }

    // Call gzsetparams
    gzFile file = gzdopen(1, "wb"); // Use stdout as dummy gzFile
    if (file) {
        ret = gzsetparams(file, level, strategy);
        if (ret != Z_OK) {
            gzclose(file);
            inflateEnd(&strm);
            free(dictionary);
            return 0;
        }
        gzclose(file);
    }

    // Call crc32_combine_gen
    uLong crc_gen = crc32_combine_gen(len2);
    (void)crc_gen; // Suppress unused variable warning

    // Call deflateSetDictionary
    ret = deflateSetDictionary(&strm, dictionary, dictLength);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        free(dictionary);
        return 0;
    }

    // Call deflateSetHeader
    ret = deflateSetHeader(&strm, &header);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        free(dictionary);
        return 0;
    }

    // Clean up
    inflateEnd(&strm);
    free(dictionary);

    return 0;
}
