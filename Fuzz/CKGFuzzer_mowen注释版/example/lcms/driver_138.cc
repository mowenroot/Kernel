#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint32_t from the fuzz input
uint32_t SafeExtractUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Default value if not enough data
    }
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a double from the fuzz input
double SafeExtractDouble(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Default value if not enough data
    }
    double value;
    memcpy(&value, data + offset, sizeof(double));
    offset += sizeof(double);
    return value;
}

// Function to safely extract a cmsCIExyY from the fuzz input
cmsCIExyY SafeExtractCIExyY(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyY xyY;
    if (offset + sizeof(cmsCIExyY) > size) {
        xyY.x = 0.0;
        xyY.y = 0.0;
        xyY.Y = 0.0;
        return xyY; // Default value if not enough data
    }
    memcpy(&xyY, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return xyY;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = nullptr;
    cmsToneCurve* toneCurve = nullptr;
    cmsHPROFILE hDeviceLink = nullptr;

    // Extract inputs from fuzz data
    uint32_t intent = SafeExtractUInt32(data, size, offset);
    uint32_t usedDirection = SafeExtractUInt32(data, size, offset);
    cmsCIExyY whitePoint = SafeExtractCIExyY(data, size, offset);
    double limit = SafeExtractDouble(data, size, offset);

    // Create a Lab profile
    hProfile = cmsCreateLab2ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Check if the intent is supported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);

    // Create a tone curve (dummy implementation for fuzzing)
    toneCurve = cmsBuildGamma(nullptr, 2.2);
    if (!toneCurve) {
        cmsCloseProfile(hProfile);
        return 0; // Failed to create tone curve
    }

    // Check if the tone curve is multisegment
    cmsBool isMultisegment = cmsIsToneCurveMultisegment(toneCurve);

    // Check if the tone curve is monotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);

    // Create an ink limiting device link
    hDeviceLink = cmsCreateInkLimitingDeviceLinkTHR(nullptr, cmsSigCmykData, limit);
    if (!hDeviceLink) {
        cmsFreeToneCurve(toneCurve);
        cmsCloseProfile(hProfile);
        return 0; // Failed to create device link
    }

    // Clean up resources
    cmsFreeToneCurve(toneCurve);
    cmsCloseProfile(hProfile);
    cmsCloseProfile(hDeviceLink);

    return 0;
}
