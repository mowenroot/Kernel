#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory and initialize it
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size * sizeof(T)));
    if (!ptr) {
        return nullptr;
    }
    memset(ptr, 0, size * sizeof(T));
    return ptr;
}

// Function to safely free memory
template <typename T>
void safe_free(T* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data from fuzz input
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 32) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsUInt32Number Intent = 0;
    cmsUInt32Number UsedDirection = 0;
    cmsUInt32Number nMax = 0;
    cmsUInt32Number* Codes = nullptr;
    char** Descriptions = nullptr;
    cmsCIELab Lab = {0.0, 0.0, 0.0};
    cmsUInt8Number ProfileID[16] = {0};

    // Extract data from fuzz input
    Intent = data[0];
    UsedDirection = data[1];
    nMax = data[2];
    safe_copy(&Lab, data + 3, sizeof(cmsCIELab));

    // Allocate memory for Codes and Descriptions
    Codes = safe_malloc<cmsUInt32Number>(nMax);
    Descriptions = safe_malloc<char*>(nMax);
    if (!Codes || !Descriptions) {
        goto cleanup;
    }

    // Call cmsIsIntentSupported
    if (cmsIsIntentSupported(hProfile, Intent, UsedDirection)) {
        // Handle success
    }

    // Call cmsGetSupportedIntentsTHR
    if (cmsGetSupportedIntentsTHR(nullptr, nMax, Codes, Descriptions) > 0) {
        // Handle success
    }

    // Call cmsIsCLUT
    if (cmsIsCLUT(hProfile, Intent, UsedDirection)) {
        // Handle success
    }

    // Call cmsGetHeaderProfileID
    cmsGetHeaderProfileID(hProfile, ProfileID);

    // Call cmsDesaturateLab
    if (cmsDesaturateLab(&Lab, 127.0, -128.0, 127.0, -128.0)) {
        // Handle success
    }

cleanup:
    // Free allocated memory
    safe_free(Codes);
    safe_free(Descriptions);

    return 0;
}
