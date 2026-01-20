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

// Function to safely reallocate memory
void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(ptr);
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size < 1) {
        return 0;
    }

    // Initialize variables
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    // Allocate memory for the dictionary and compressed data
    uint8_t* dictionary = (uint8_t*)safe_malloc(size);
    uint8_t* compressed_data = (uint8_t*)safe_malloc(compressBound(size));
    uLongf compressed_size = compressBound(size);

    // Copy the input data to the dictionary
    memcpy(dictionary, data, size);

    // Initialize the compression stream
    int ret = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        safe_free(dictionary);
        safe_free(compressed_data);
        return 0;
    }

    // Set the dictionary
    ret = deflateSetDictionary(&stream, dictionary, size);
    if (ret != Z_OK) {
        deflateEnd(&stream);
        safe_free(dictionary);
        safe_free(compressed_data);
        return 0;
    }

    // Compress the data
    ret = compress2(compressed_data, &compressed_size, dictionary, size, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        deflateEnd(&stream);
        safe_free(dictionary);
        safe_free(compressed_data);
        return 0;
    }

    // Calculate the upper bound for the compressed size
    uLong bound = deflateBound(&stream, size);
    if (bound < compressed_size) {
        deflateEnd(&stream);
        safe_free(dictionary);
        safe_free(compressed_data);
        return 0;
    }

    // Clean up
    deflateEnd(&stream);
    safe_free(dictionary);
    safe_free(compressed_data);

    return 0;
}
