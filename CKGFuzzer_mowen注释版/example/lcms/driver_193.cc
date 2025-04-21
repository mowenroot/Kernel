#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int32_t safe_extract_int(const uint8_t* data, size_t size, size_t& offset, int32_t min, int32_t max) {
    if (offset + sizeof(int32_t) > size) {
        return min; // Default to minimum value if not enough data
    }
    int32_t value = *reinterpret_cast<const int32_t*>(data + offset);
    offset += sizeof(int32_t);
    return (value < min) ? min : ((value > max) ? max : value);
}

// Function to safely extract a float from the fuzz input
float safe_extract_float(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Default to 0.0 if not enough data
    }
    float value = *reinterpret_cast<const float*>(data + offset);
    offset += sizeof(float);
    return value;
}

// Function to safely extract a cmsHPROFILE from the fuzz input
cmsHPROFILE safe_extract_profile(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsHPROFILE) > size) {
        return nullptr; // Default to nullptr if not enough data
    }
    cmsHPROFILE profile = *reinterpret_cast<const cmsHPROFILE*>(data + offset);
    offset += sizeof(cmsHPROFILE);
    return profile;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE profile = nullptr;
    cmsCIEXYZ blackPoint;
    cmsToneCurve* curves[cmsMAXCHANNELS] = {nullptr};

    // Extract profile handle
    profile = safe_extract_profile(data, size, offset);
    if (!profile) {
        return 0; // No valid profile, exit early
    }

    // Extract intent and direction for cmsIsCLUT
    cmsUInt32Number intent = safe_extract_int(data, size, offset, 0, 100);
    cmsUInt32Number direction = safe_extract_int(data, size, offset, 0, 100);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(profile, intent, direction);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(profile);

    // Extract intent and flags for cmsDetectBlackPoint
    cmsUInt32Number bpIntent = safe_extract_int(data, size, offset, 0, 100);
    cmsUInt32Number bpFlags = safe_extract_int(data, size, offset, 0, 100);

    // Call cmsDetectBlackPoint
    cmsBool blackPointDetected = cmsDetectBlackPoint(&blackPoint, profile, bpIntent, bpFlags);

    // Extract color space for cmsCreateLinearizationDeviceLink
    cmsColorSpaceSignature colorSpace = static_cast<cmsColorSpaceSignature>(safe_extract_int(data, size, offset, 0, 100));

    // Create tone curves for cmsCreateLinearizationDeviceLink
    for (int i = 0; i < cmsMAXCHANNELS; ++i) {
        float gamma = safe_extract_float(data, size, offset);
        curves[i] = cmsBuildGamma(nullptr, gamma);
    }

    // Call cmsCreateLinearizationDeviceLink
    cmsHPROFILE linearizationProfile = cmsCreateLinearizationDeviceLink(colorSpace, curves);

    // Clean up
    if (linearizationProfile) {
        cmsCloseProfile(linearizationProfile);
    }
    for (int i = 0; i < cmsMAXCHANNELS; ++i) {
        if (curves[i]) {
            cmsFreeToneCurve(curves[i]);
        }
    }

    return 0;
}
