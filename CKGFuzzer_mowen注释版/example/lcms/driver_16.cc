#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a tone curve
cmsToneCurve* safe_tone_curve_alloc(cmsContext contextID, cmsUInt32Number nEntries) {
    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(contextID, nEntries, nullptr);
    if (!curve) return nullptr;
    return curve;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 16) return 0;

    // Initialize the context
    cmsContext contextID = cmsCreateContext(nullptr, nullptr);
    if (!contextID) return 0;

    // Load IT8 data from memory
    cmsHANDLE hIT8 = cmsIT8LoadFromMem(contextID, data, size);
    if (!hIT8) {
        cmsDeleteContext(contextID);
        return 0;
    }

    // Set data format for the IT8 container
    char* sampleFormat = safe_strndup(data, size); // Changed from const char* to char*
    if (sampleFormat) {
        cmsIT8SetDataFormat(hIT8, 0, sampleFormat);
        free(sampleFormat); // Corrected the type to match malloc's return type
    }

    // Create and smooth a tone curve
    cmsToneCurve* toneCurve = safe_tone_curve_alloc(contextID, 256);
    if (toneCurve) {
        cmsSmoothToneCurve(toneCurve, 0.5);
        cmsIsToneCurveMonotonic(toneCurve);
        cmsFreeToneCurve(toneCurve);
    }

    // Save IT8 data to memory
    cmsUInt32Number bytesNeeded = 0;
    cmsIT8SaveToMem(hIT8, nullptr, &bytesNeeded);
    if (bytesNeeded > 0) {
        std::unique_ptr<uint8_t[]> buffer(new uint8_t[bytesNeeded]);
        cmsIT8SaveToMem(hIT8, buffer.get(), &bytesNeeded);
    }

    // Clean up resources
    cmsIT8Free(hIT8);
    cmsDeleteContext(contextID);

    return 0;
}
