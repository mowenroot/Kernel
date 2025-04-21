#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h> // Added for fprintf

// Function to safely allocate memory
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data
void safeCopy(void* dest, const void* src, size_t size) {
    if (memcpy(dest, src, size) != dest) {
        fprintf(stderr, "Memory copy failed\n");
        exit(EXIT_FAILURE);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 16) {
        return 0;
    }

    // Initialize variables
    cmsHTRANSFORM transform = nullptr;
    cmsHPROFILE inputProfile = nullptr, outputProfile = nullptr;
    cmsToneCurve* toneCurve = nullptr;
    cmsHPROFILE deviceLinkProfile = nullptr;
    uint8_t* inputBuffer = nullptr;
    uint8_t* outputBuffer = nullptr;
    cmsUInt32Number inputFormat, outputFormat;
    cmsUInt32Number intent = INTENT_PERCEPTUAL; // Corrected intent
    cmsUInt32Number flags = cmsFLAGS_NOCACHE;
    cmsFloat64Number lambda = 0.5; // Example lambda value for smoothing

    // Derive input and output formats from the fuzz input
    inputFormat = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    outputFormat = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];

    // Create profiles
    inputProfile = cmsCreate_sRGBProfile();
    outputProfile = cmsCreate_sRGBProfile();
    if (!inputProfile || !outputProfile) {
        goto cleanup;
    }

    // Create transform
    transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);
    if (!transform) {
        goto cleanup;
    }

    // Create tone curve
    toneCurve = cmsBuildGamma(nullptr, 2.2);
    if (!toneCurve) {
        goto cleanup;
    }

    // Smooth tone curve
    if (!cmsSmoothToneCurve(toneCurve, lambda)) {
        goto cleanup;
    }

    // Check if tone curve is monotonic
    if (!cmsIsToneCurveMonotonic(toneCurve)) {
        goto cleanup;
    }

    // Allocate buffers
    inputBuffer = (uint8_t*)safeMalloc(size);
    outputBuffer = (uint8_t*)safeMalloc(size);
    if (!inputBuffer || !outputBuffer) {
        goto cleanup;
    }

    // Copy input data to buffer
    safeCopy(inputBuffer, data + 8, size - 8);

    // Perform transform
    cmsDoTransform(transform, inputBuffer, outputBuffer, size - 8);

    // Create device link profile
    deviceLinkProfile = cmsTransform2DeviceLink(transform, 4.0, flags);
    if (!deviceLinkProfile) {
        goto cleanup;
    }

cleanup:
    // Free resources
    if (transform) cmsDeleteTransform(transform);
    if (inputProfile) cmsCloseProfile(inputProfile);
    if (outputProfile) cmsCloseProfile(outputProfile);
    if (toneCurve) cmsFreeToneCurve(toneCurve);
    if (deviceLinkProfile) cmsCloseProfile(deviceLinkProfile);
    safeFree(inputBuffer);
    safeFree(outputBuffer);

    return 0;
}
