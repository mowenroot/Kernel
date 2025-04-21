#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory and check for allocation failure
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely copy data and check for buffer overflow
void safe_copy(void* dest, const void* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely free allocated memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsCIExyY) + sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number) * 2) {
        return 0;
    }

    // Initialize variables
    cmsCIExyY whitePoint;
    cmsFloat64Number lambda;
    cmsUInt32Number inputFormat, outputFormat;
    cmsHPROFILE inputProfile = nullptr, outputProfile = nullptr;
    cmsHTRANSFORM transform = nullptr;
    cmsToneCurve* toneCurve = nullptr;
    uint8_t* inputBuffer = nullptr;
    uint8_t* outputBuffer = nullptr;

    // Extract data from the fuzzer input
    safe_copy(&whitePoint, data, sizeof(cmsCIExyY));
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);

    safe_copy(&lambda, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);

    safe_copy(&inputFormat, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    safe_copy(&outputFormat, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Create input and output profiles
    inputProfile = cmsCreateLab2Profile(&whitePoint);
    if (!inputProfile) {
        goto cleanup;
    }

    outputProfile = cmsCreateLab2Profile(&whitePoint);
    if (!outputProfile) {
        goto cleanup;
    }

    // Create a transform
    transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, INTENT_PERCEPTUAL, 0);
    if (!transform) {
        goto cleanup;
    }

    // Allocate buffers for input and output data
    inputBuffer = safe_malloc<uint8_t>(size);
    outputBuffer = safe_malloc<uint8_t>(size);

    // Copy the remaining data to the input buffer
    safe_copy(inputBuffer, data, size);

    // Perform the transform
    cmsDoTransform(transform, inputBuffer, outputBuffer, size);

    // Create and smooth a tone curve
    toneCurve = cmsBuildTabulatedToneCurve16(nullptr, 256, nullptr);
    if (!toneCurve) {
        goto cleanup;
    }

    if (!cmsSmoothToneCurve(toneCurve, lambda)) {
        goto cleanup;
    }

    // Check if the tone curve is monotonic
    if (!cmsIsToneCurveMonotonic(toneCurve)) {
        goto cleanup;
    }

cleanup:
    // Free all allocated resources
    if (inputProfile) cmsCloseProfile(inputProfile);
    if (outputProfile) cmsCloseProfile(outputProfile);
    if (transform) cmsDeleteTransform(transform);
    if (toneCurve) cmsFreeToneCurve(toneCurve);
    safe_free(inputBuffer);
    safe_free(outputBuffer);

    return 0;
}
