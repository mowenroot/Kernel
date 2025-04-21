#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely reallocate memory
void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(ptr);
        exit(1);
    }
    return new_ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsTagSignature tagSig;
    cmsUInt32Number tagSize;
    void* tagData = nullptr;
    cmsBool result;

    // Extract tag signature and size from the input data
    memcpy(&tagSig, data, sizeof(cmsTagSignature));
    memcpy(&tagSize, data + sizeof(cmsTagSignature), sizeof(cmsUInt32Number));

    // Ensure the tag size is within a reasonable limit
    if (tagSize > size - sizeof(cmsTagSignature) - sizeof(cmsUInt32Number)) {
        tagSize = size - sizeof(cmsTagSignature) - sizeof(cmsUInt32Number);
    }

    // Create a new ICC profile
    hProfile = cmsCreateProfilePlaceholder(nullptr);
    if (!hProfile) {
        return 0;
    }

    // Allocate memory for the tag data
    tagData = safe_malloc(tagSize);
    if (!tagData) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Copy the tag data from the input
    memcpy(tagData, data + sizeof(cmsTagSignature) + sizeof(cmsUInt32Number), tagSize);

    // Write the raw tag to the profile
    result = cmsWriteRawTag(hProfile, tagSig, tagData, tagSize);
    if (!result) {
        safe_free(tagData);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Read the raw tag back from the profile
    cmsUInt32Number readSize = cmsReadRawTag(hProfile, tagSig, nullptr, 0);
    if (readSize != tagSize) {
        safe_free(tagData);
        cmsCloseProfile(hProfile);
        return 0;
    }

    void* readData = safe_malloc(readSize);
    if (!readData) {
        safe_free(tagData);
        cmsCloseProfile(hProfile);
        return 0;
    }

    readSize = cmsReadRawTag(hProfile, tagSig, readData, readSize);
    if (readSize != tagSize) {
        safe_free(tagData);
        safe_free(readData);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Compare the written and read data
    if (memcmp(tagData, readData, tagSize) != 0) {
        safe_free(tagData);
        safe_free(readData);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Check if the profile supports a specific rendering intent
    cmsBool isCLUTSupported = cmsIsCLUT(hProfile, INTENT_PERCEPTUAL, LCMS_USED_AS_OUTPUT);

    // Detect Total Area Coverage (TAC)
    cmsFloat64Number tac = cmsDetectTAC(hProfile);

    // Clean up
    safe_free(tagData);
    safe_free(readData);
    cmsCloseProfile(hProfile);

    return 0;
}
