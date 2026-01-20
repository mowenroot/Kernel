#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a float from the fuzz input
float safe_extract_float(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Default value if not enough data
    }
    float value;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return value;
}

// Function to safely extract an integer from the fuzz input
uint32_t safe_extract_uint32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Default value if not enough data
    }
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Extract inputs from fuzz data
    float version = safe_extract_float(data, size, offset);
    uint32_t flags = safe_extract_uint32(data, size, offset);
    float lambda = safe_extract_float(data, size, offset);

    // Set profile version
    cmsSetProfileVersion(hProfile, version);

    // Set header flags
    cmsSetHeaderFlags(hProfile, flags);

    // Create a tone curve
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2);
    if (!toneCurve) {
        cmsCloseProfile(hProfile);
        return 0; // Failed to create tone curve
    }

    // Smooth the tone curve
    if (!cmsSmoothToneCurve(toneCurve, lambda)) {
        cmsFreeToneCurve(toneCurve);
        cmsCloseProfile(hProfile);
        return 0; // Smoothing failed
    }

    // Get the number of entries in the tone curve
    cmsUInt32Number entries = cmsGetToneCurveEstimatedTableEntries(toneCurve);

    // Check if the tone curve is monotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);

    // Clean up resources
    cmsFreeToneCurve(toneCurve);
    cmsCloseProfile(hProfile);

    return 0;
}
