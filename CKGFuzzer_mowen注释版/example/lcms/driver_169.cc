#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int32_t extractInt(const uint8_t* data, size_t size, size_t& offset, size_t intSize) {
    if (offset + intSize > size) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = 0;
    for (size_t i = 0; i < intSize; ++i) {
        value |= (data[offset++] << (8 * i));
    }
    return value;
}

// Function to safely extract a float from the fuzz input
float extractFloat(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Return a default value if not enough data
    }
    float value;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0; // Early exit if profile creation fails
    }

    // Extract inputs from fuzz data
    cmsUInt32Number Intent = extractInt(data, size, offset, sizeof(cmsUInt32Number));
    cmsUInt32Number UsedDirection = extractInt(data, size, offset, sizeof(cmsUInt32Number));
    cmsProfileClassSignature DeviceClass = static_cast<cmsProfileClassSignature>(extractInt(data, size, offset, sizeof(cmsProfileClassSignature)));
    cmsFloat32Number ToneCurveValue = extractFloat(data, size, offset);

    // Call cmsSetDeviceClass
    cmsSetDeviceClass(hProfile, DeviceClass);

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsDetectDestinationBlackPoint
    cmsCIEXYZ BlackPoint;
    cmsBool blackPointDetected = cmsDetectDestinationBlackPoint(&BlackPoint, hProfile, Intent, 0);

    // Call cmsEvalToneCurveFloat
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2); // Example tone curve
    if (toneCurve) {
        cmsFloat32Number evalResult = cmsEvalToneCurveFloat(toneCurve, ToneCurveValue);
        cmsFreeToneCurve(toneCurve);
    }

    // Clean up resources
    cmsCloseProfile(hProfile);

    return 0; // Return 0 to indicate success
}
