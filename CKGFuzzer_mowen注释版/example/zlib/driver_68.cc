#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <memory>

// Function to safely allocate memory and handle errors
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        std::cerr << "Memory allocation failed." << std::endl;
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

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize variables
    const char* version = zlibVersion();
    if (!version) {
        std::cerr << "zlibVersion returned NULL." << std::endl;
        return 0;
    }

    uLong compileFlags = zlibCompileFlags();
    if (compileFlags == 0) {
        std::cerr << "zlibCompileFlags returned 0." << std::endl;
        return 0;
    }

    // Allocate memory for the destination buffer
    uLongf destLen = size * 2; // Assume the decompressed data is at most twice the size of the compressed data
    std::unique_ptr<Bytef[]> dest(new Bytef[destLen]);
    if (!dest) {
        std::cerr << "Failed to allocate memory for destination buffer." << std::endl;
        return 0;
    }

    // Perform decompression
    int ret = uncompress(dest.get(), &destLen, data, size);
    if (ret != Z_OK) {
        const char* errorMsg = zError(ret);
        std::cerr << "uncompress failed with error: " << (errorMsg ? errorMsg : "Unknown error") << std::endl;
        return 0;
    }

    // Perform decompression with uncompress2 for additional coverage
    uLongf destLen2 = size * 2;
    std::unique_ptr<Bytef[]> dest2(new Bytef[destLen2]);
    if (!dest2) {
        std::cerr << "Failed to allocate memory for destination buffer." << std::endl;
        return 0;
    }

    uLong sourceLen = size;
    ret = uncompress2(dest2.get(), &destLen2, data, &sourceLen);
    if (ret != Z_OK) {
        const char* errorMsg = zError(ret);
        std::cerr << "uncompress2 failed with error: " << (errorMsg ? errorMsg : "Unknown error") << std::endl;
        return 0;
    }

    // All operations completed successfully
    return 0;
}
