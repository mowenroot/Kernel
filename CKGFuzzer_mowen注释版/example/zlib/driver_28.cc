#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include this header for 'stderr'

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
    // Ensure input size is valid
    if (size < 1) {
        return 0;
    }

    // Initialize variables
    gzFile gz_file = gzopen("output_file", "wb");
    if (!gz_file) {
        return 0;
    }

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        gzclose(gz_file);
        return 0;
    }

    // Use gzputc to write a character to the gzFile
    int c = data[0] % 256; // Ensure c is within valid range
    ret = gzputc(gz_file, c);
    if (ret == -1) {
        deflateEnd(&strm);
        gzclose(gz_file);
        return 0;
    }

    // Use gzgets to read a line from the gzFile
    char* buf = (char*)safe_malloc(size + 1);
    if (gzgets(gz_file, buf, size) == NULL) {  // Corrected the assignment to a comparison
        safe_free(buf);
        deflateEnd(&strm);
        gzclose(gz_file);
        return 0;
    }
    safe_free(buf);

    // Use inflateReset2 to reset the inflate state
    ret = inflateReset2(&strm, 15);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        gzclose(gz_file);
        return 0;
    }

    // Use deflateParams to adjust compression level and strategy
    ret = deflateParams(&strm, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        gzclose(gz_file);
        return 0;
    }

    // Use crc32_z to compute the CRC-32 checksum
    unsigned long crc = crc32_z(0L, data, size);
    if (crc == 0) {
        deflateEnd(&strm);
        gzclose(gz_file);
        return 0;
    }

    // Clean up
    deflateEnd(&strm);
    gzclose(gz_file);

    return 0;
}
