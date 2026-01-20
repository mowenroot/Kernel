#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to a double
double safe_atof(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return 0.0;
    double value = atof(str);
    free(str);
    return value;
}

// Function to safely convert fuzz input to an integer
int safe_atoi(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for all operations
    if (size < 100) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsMLU* mlu = nullptr;
    cmsHANDLE hIT8 = nullptr;
    cmsCIEXYZ BlackPoint;
    double propertyDbl = 0.0;
    int intent = safe_atoi(data, 4);
    int usedDirection = safe_atoi(data + 4, 4);
    const char* propertyStr = (const char*)data + 8;

    // Create a dummy profile for testing
    hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    // Test cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);
    if (isIntentSupported) {
        // Additional logic if needed
    }

    // Test cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);
    if (isMatrixShaper) {
        // Additional logic if needed
    }

    // Test cmsDetectBlackPoint
    cmsBool blackPointDetected = cmsDetectBlackPoint(&BlackPoint, hProfile, intent, 0);
    if (blackPointDetected) {
        // Additional logic if needed
    }

    // Create a dummy IT8 handle for testing
    hIT8 = cmsIT8Alloc(0);
    if (!hIT8) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Test cmsIT8GetPropertyDbl
    propertyDbl = cmsIT8GetPropertyDbl(hIT8, propertyStr);
    // Additional logic if needed

    // Create a dummy MLU for testing
    mlu = cmsMLUalloc(0, 1);
    if (!mlu) {
        cmsIT8Free(hIT8);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Test cmsMLUfree
    cmsMLUfree(mlu);

    // Clean up
    cmsIT8Free(hIT8);
    cmsCloseProfile(hProfile);

    return 0;
}
