#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely copy memory
void safeMemcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely free memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Allocate memory for the profile data
    void* profileData = safeMalloc(size);
    safeMemcpy(profileData, data, size);

    // Open the profile from memory
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(profileData, size);
    if (!hProfile) {
        safeFree(profileData);
        return 0;
    }

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Get the tag signature at index 0
    cmsTagSignature tagSig = cmsGetTagSignature(hProfile, 0);

    // Allocate memory for the tag data
    const size_t tagBufferSize = 1024;
    void* tagBuffer = safeMalloc(tagBufferSize);

    // Read raw tag data
    cmsUInt32Number tagSize = cmsReadRawTag(hProfile, tagSig, tagBuffer, tagBufferSize);
    if (tagSize == 0) {
        cmsCloseProfile(hProfile);
        safeFree(profileData);
        safeFree(tagBuffer);
        return 0;
    }

    // Write the tag back to the profile
    cmsBool writeSuccess = cmsWriteTag(hProfile, tagSig, tagBuffer);
    if (!writeSuccess) {
        cmsCloseProfile(hProfile);
        safeFree(profileData);
        safeFree(tagBuffer);
        return 0;
    }

    // Clean up resources
    cmsCloseProfile(hProfile);
    safeFree(profileData);
    safeFree(tagBuffer);

    return 0;
}
