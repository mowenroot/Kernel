#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* SafeStrndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert a double from fuzz input
cmsFloat64Number SafeDouble(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    char buffer[32]; // Assuming a reasonable size for a double string representation
    size_t copy_size = size < sizeof(buffer) - 1 ? size : sizeof(buffer) - 1;
    memcpy(buffer, data, copy_size);
    buffer[copy_size] = '\0';
    return strtod(buffer, nullptr);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 32) return 0;

    // Initialize variables
    cmsHANDLE hIT8 = cmsIT8Alloc(nullptr); // Corrected to pass nullptr as ContextID
    if (!hIT8) return 0;

    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) {
        cmsIT8Free(hIT8);
        return 0;
    }

    cmsCIEXYZ BlackPoint;
    memset(&BlackPoint, 0, sizeof(BlackPoint));

    // Extract strings and double from fuzz input
    char* patch = SafeStrndup(data, 8);
    char* sample = SafeStrndup(data + 8, 8);
    char* val = SafeStrndup(data + 16, 8);
    cmsFloat64Number dblVal = SafeDouble(data + 24, 8);
    char* comment = SafeStrndup(data + 32, size - 32);

    // Ensure all strings are valid
    if (!patch || !sample || !val || !comment) {
        free(patch);
        free(sample);
        free(val);
        free(comment);
        cmsCloseProfile(hProfile);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Call APIs with error handling
    if (!cmsIT8SetData(hIT8, patch, sample, val)) {
        // Handle error
    }

    if (!cmsIT8SetPropertyDbl(hIT8, "Property", dblVal)) {
        // Handle error
    }

    if (!cmsIsMatrixShaper(hProfile)) {
        // Handle error
    }

    if (!cmsDetectBlackPoint(&BlackPoint, hProfile, INTENT_PERCEPTUAL, 0)) {
        // Handle error
    }

    if (!cmsIT8SetComment(hIT8, comment)) {
        // Handle error
    }

    // Clean up
    free(patch);
    free(sample);
    free(val);
    free(comment);
    cmsCloseProfile(hProfile);
    cmsIT8Free(hIT8);

    return 0;
}
