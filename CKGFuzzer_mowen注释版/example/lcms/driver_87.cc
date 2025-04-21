#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
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
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsUInt32Number) * 4) {
        return 0;
    }

    // Extract parameters from the fuzz input
    cmsUInt32Number inputFormat = *reinterpret_cast<const cmsUInt32Number*>(data);
    cmsUInt32Number outputFormat = *reinterpret_cast<const cmsUInt32Number*>(data + sizeof(cmsUInt32Number));
    cmsUInt32Number intent = *reinterpret_cast<const cmsUInt32Number*>(data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number flags = *reinterpret_cast<const cmsUInt32Number*>(data + 3 * sizeof(cmsUInt32Number));

    // Create profiles
    cmsHPROFILE inputProfile = cmsCreateProfilePlaceholder(NULL); // Changed TRUE to NULL
    cmsHPROFILE outputProfile = cmsCreateProfilePlaceholder(NULL); // Changed TRUE to NULL

    if (!inputProfile || !outputProfile) {
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Create transform
    cmsHTRANSFORM transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);
    if (!transform) {
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Allocate buffers for transformation
    size_t bufferSize = size - 4 * sizeof(cmsUInt32Number);
    void* inputBuffer = safe_malloc(bufferSize);
    void* outputBuffer = safe_malloc(bufferSize);

    // Copy the remaining data to the input buffer
    safe_memcpy(inputBuffer, data + 4 * sizeof(cmsUInt32Number), bufferSize);

    // Perform transformation
    cmsDoTransform(transform, inputBuffer, outputBuffer, bufferSize);

    // Read and write tags
    cmsTagSignature tagSig = cmsSigChromaticityTag;
    void* tagData = cmsReadTag(inputProfile, tagSig);
    if (tagData) {
        cmsWriteTag(outputProfile, tagSig, tagData);
    }

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);
    safe_free(inputBuffer);
    safe_free(outputBuffer);

    return 0;
}
