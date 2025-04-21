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

// Function to safely create a tone curve from fuzz input
cmsToneCurve* create_tone_curve(cmsContext ContextID, const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(ContextID, size / 2, (cmsUInt16Number*)data);
    return curve;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize context and variables
    cmsContext ContextID = cmsCreateContext(nullptr, nullptr);
    if (!ContextID) return 0;

    cmsHPROFILE hProfile = nullptr;
    cmsHANDLE hIT8 = nullptr;
    cmsUInt64Number flags = 0;
    cmsToneCurve* curve = nullptr;
    char* key = nullptr;
    char* buffer = nullptr;
    char* sample = nullptr;

    // Ensure we have enough data for basic operations
    if (size < 16) {
        cmsDeleteContext(ContextID);
        return 0;
    }

    // Create a tone curve from the fuzz input
    curve = create_tone_curve(ContextID, data, size / 2);
    if (!curve) {
        cmsDeleteContext(ContextID);
        return 0;
    }

    // Create a linearization device link profile
    hProfile = cmsCreateLinearizationDeviceLinkTHR(ContextID, cmsSigRgbData, &curve);
    if (!hProfile) {
        cmsFreeToneCurve(curve);
        cmsDeleteContext(ContextID);
        return 0;
    }

    // Get header attributes
    cmsGetHeaderAttributes(hProfile, &flags);

    // Create an IT8 handle
    hIT8 = cmsIT8Alloc(ContextID);
    if (!hIT8) {
        cmsCloseProfile(hProfile);
        cmsFreeToneCurve(curve);
        cmsDeleteContext(ContextID);
        return 0;
    }

    // Set uncooked property
    key = safe_strndup(data + size / 2, size / 4);
    buffer = safe_strndup(data + 3 * size / 4, size / 4);
    if (key && buffer) {
        cmsIT8SetPropertyUncooked(hIT8, key, buffer);
    }

    // Set data format
    sample = safe_strndup(data, size / 4);
    if (sample) {
        cmsIT8SetDataFormat(hIT8, 0, sample);
    }

    // Set table
    cmsIT8SetTable(hIT8, 0);

    // Clean up
    free(key);
    free(buffer);
    free(sample);
    cmsIT8Free(hIT8);
    cmsCloseProfile(hProfile);
    cmsFreeToneCurve(curve);
    cmsDeleteContext(ContextID);

    return 0;
}
