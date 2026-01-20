#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzz input to a specific type
template <typename T>
T safe_convert(const uint8_t*& data, size_t& size, bool is_signed = false) {
    if (size < sizeof(T)) {
        abort(); // Insufficient data
    }
    T value;
    memcpy(&value, data, sizeof(T));
    data += sizeof(T);
    size -= sizeof(T);
    if (is_signed) {
        // Handle sign extension for signed types
        if (sizeof(T) < sizeof(int32_t)) {
            int32_t temp = static_cast<int32_t>(value);
            value = static_cast<T>(temp);
        }
    }
    return value;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the minimum required input
    if (size < sizeof(cmsUInt32Number) * 5 + sizeof(cmsUInt16Number) * 3) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsCIELab Lab;
    cmsUInt16Number wLab[3];
    cmsUInt32Number Intent, UsedDirection;
    double amax, amin, bmax, bmin;

    // Extract inputs from fuzz data
    Intent = safe_convert<cmsUInt32Number>(data, size);
    UsedDirection = safe_convert<cmsUInt32Number>(data, size);
    wLab[0] = safe_convert<cmsUInt16Number>(data, size);
    wLab[1] = safe_convert<cmsUInt16Number>(data, size);
    wLab[2] = safe_convert<cmsUInt16Number>(data, size);
    amax = safe_convert<double>(data, size);
    amin = safe_convert<double>(data, size);
    bmax = safe_convert<double>(data, size);
    bmin = safe_convert<double>(data, size);

    // Create a dummy profile for testing purposes
    hProfile = cmsCreateLab4Profile(nullptr);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Test cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);
    if (isIntentSupported) {
        // Handle supported intent
    }

    // Test cmsLabEncoded2FloatV2
    cmsLabEncoded2FloatV2(&Lab, wLab);

    // Test cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);
    if (isCLUT) {
        // Handle CLUT support
    }

    // Test cmsDesaturateLab
    cmsBool desaturated = cmsDesaturateLab(&Lab, amax, amin, bmax, bmin);
    if (desaturated) {
        // Handle desaturated Lab
    }

    // Test cmsDetectTAC
    cmsFloat64Number tac = cmsDetectTAC(hProfile);
    if (tac > 0) {
        // Handle TAC detection
    }

    // Clean up resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
