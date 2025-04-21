#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a double from the fuzz input
double extractDouble(const uint8_t*& data, size_t& size) {
    if (size < sizeof(double)) {
        return 0.0; // Return a default value if not enough data
    }
    double value;
    memcpy(&value, data, sizeof(double));
    data += sizeof(double);
    size -= sizeof(double);
    return value;
}

// Function to safely extract an integer from the fuzz input
cmsUInt32Number extractUInt32(const uint8_t*& data, size_t& size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0; // Return a default value if not enough data
    }
    cmsUInt32Number value;
    memcpy(&value, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);
    return value;
}

// Function to safely extract a cmsCIExyY structure from the fuzz input
cmsCIExyY extractCIExyY(const uint8_t*& data, size_t& size) {
    cmsCIExyY xyY;
    if (size < sizeof(cmsCIExyY)) {
        memset(&xyY, 0, sizeof(cmsCIExyY)); // Initialize to zero if not enough data
    } else {
        memcpy(&xyY, data, sizeof(cmsCIExyY));
        data += sizeof(cmsCIExyY);
        size -= sizeof(cmsCIExyY);
    }
    return xyY;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsToneCurve* toneCurve = nullptr;
    cmsFloat64Number tac = 0.0;
    cmsBool isMonotonic = FALSE;

    // Extract parameters from fuzz input
    cmsUInt32Number nLUTPoints = extractUInt32(data, size);
    cmsFloat64Number Bright = extractDouble(data, size);
    cmsFloat64Number Contrast = extractDouble(data, size);
    cmsFloat64Number Hue = extractDouble(data, size);
    cmsFloat64Number Saturation = extractDouble(data, size);
    cmsUInt32Number TempSrc = extractUInt32(data, size);
    cmsUInt32Number TempDest = extractUInt32(data, size);
    cmsCIExyY WhitePoint = extractCIExyY(data, size);
    cmsFloat64Number lambda = extractDouble(data, size);

    // Create BCHSW abstract profile
    hProfile = cmsCreateBCHSWabstractProfile(nLUTPoints, Bright, Contrast, Hue, Saturation, TempSrc, TempDest);
    if (!hProfile) {
        goto cleanup;
    }

    // Create Lab4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, &WhitePoint);
    if (!hProfile) {
        goto cleanup;
    }

    // Create and smooth tone curve
    toneCurve = cmsBuildGamma(nullptr, 2.2); // Example gamma curve
    if (!toneCurve) {
        goto cleanup;
    }
    if (!cmsSmoothToneCurve(toneCurve, lambda)) {
        goto cleanup;
    }

    // Detect TAC
    tac = cmsDetectTAC(hProfile);
    if (tac < 0.0) {
        goto cleanup;
    }

    // Check if tone curve is monotonic
    isMonotonic = cmsIsToneCurveMonotonic(toneCurve);

cleanup:
    // Free resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }
    if (toneCurve) {
        cmsFreeToneCurve(toneCurve);
    }

    return 0; // Non-zero return values are reserved for future use.
}
