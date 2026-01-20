#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <cstdio> // Add this include to resolve 'stderr'

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

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely cast data
template <typename T>
T safe_cast(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(T) > size) {
        return T();
    }
    return *reinterpret_cast<const T*>(data + offset);
}

// Function to safely get a substring
const uint8_t* safe_substring(const uint8_t* data, size_t size, size_t offset, size_t length) {
    if (offset + length > size) {
        return nullptr;
    }
    return data + offset;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 16) {
        return 0;
    }

    // Initialize variables
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    gzFile gz_file = nullptr;
    uint8_t* dictionary = nullptr;
    uint8_t* buffer = nullptr;
    uint32_t crc1 = 0, crc2 = 0;
    int ret = Z_OK;

    // Allocate memory for the dictionary and buffer
    dictionary = static_cast<uint8_t*>(safe_malloc(size));
    buffer = static_cast<uint8_t*>(safe_malloc(size));

    // Initialize the dictionary and buffer with fuzz data
    safe_memcpy(dictionary, data, size);
    safe_memcpy(buffer, data, size);

    // Initialize the zlib stream
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        goto cleanup;
    }

    // Set the dictionary
    ret = deflateSetDictionary(&strm, dictionary, size);
    if (ret != Z_OK) {
        goto cleanup;
    }

    // Reset the inflate state
    ret = inflateReset2(&strm, 15);
    if (ret != Z_OK) {
        goto cleanup;
    }

    // Compute CRC-32 for the buffer
    crc1 = crc32_z(0L, buffer, size);

    // Combine CRC-32 checksums
    crc2 = crc32_combine(crc1, crc1, size);

    // Open a gzFile for writing
    gz_file = gzopen("output_file", "wb");
    if (!gz_file) {
        goto cleanup;
    }

    // Write data to the gzFile
    if (gzfwrite(buffer, 1, size, gz_file) != size) {
        goto cleanup;
    }

cleanup:
    // Clean up resources
    if (gz_file) {
        gzclose(gz_file);
    }
    deflateEnd(&strm);
    safe_free(dictionary);
    safe_free(buffer);

    return 0;
}
