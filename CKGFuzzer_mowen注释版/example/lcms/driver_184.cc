#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to ensure safe memory allocation
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to ensure safe memory reallocation
void* safeRealloc(void* ptr, size_t size) {
    void* newPtr = realloc(ptr, size);
    if (!newPtr) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(ptr);
        exit(EXIT_FAILURE);
    }
    return newPtr;
}

// Function to ensure safe memory deallocation
void safeFree(void* ptr) {
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
    cmsHPROFILE hProfile = nullptr;
    cmsTagSignature tagSig = (cmsTagSignature)0x58595A20; // Example tag signature
    void* rawTagData = nullptr;
    cmsUInt32Number rawTagSize = 0;
    cmsBool isCLUTSupported = FALSE;
    cmsFloat64Number tacValue = 0.0;

    // Open profile from memory
    hProfile = cmsOpenProfileFromMem(data, size);
    if (!hProfile) {
        return 0;
    }

    // Read raw tag data
    rawTagSize = cmsReadRawTag(hProfile, tagSig, nullptr, 0);
    if (rawTagSize > 0) {
        rawTagData = safeMalloc(rawTagSize);
        cmsReadRawTag(hProfile, tagSig, rawTagData, rawTagSize);
    }

    // Check if CLUT is supported
    isCLUTSupported = cmsIsCLUT(hProfile, INTENT_PERCEPTUAL, LCMS_USED_AS_OUTPUT);

    // Detect TAC
    tacValue = cmsDetectTAC(hProfile);

    // Write raw tag data back to the profile
    if (rawTagData && rawTagSize > 0) {
        cmsWriteRawTag(hProfile, tagSig, rawTagData, rawTagSize);
    }

    // Clean up
    safeFree(rawTagData);
    cmsCloseProfile(hProfile);

    return 0;
}
