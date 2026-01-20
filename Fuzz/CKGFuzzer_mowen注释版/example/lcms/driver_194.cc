#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a uint32_t value from the fuzz input
uint32_t SafeExtractUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Default value if not enough data
    }
    uint32_t value = *reinterpret_cast<const uint32_t*>(data + offset);
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a double value from the fuzz input
double SafeExtractDouble(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Default value if not enough data
    }
    double value = *reinterpret_cast<const double*>(data + offset);
    offset += sizeof(double);
    return value;
}

// Function to safely extract a profile handle from the fuzz input
cmsHPROFILE SafeExtractProfile(const uint8_t* data, size_t size, size_t& offset) {
    // For simplicity, assume profile handles are uint32_t values
    uint32_t profileHandle = SafeExtractUInt32(data, size, offset);
    return reinterpret_cast<cmsHPROFILE>(profileHandle);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE profiles[4] = {nullptr};
    cmsHTRANSFORM transform = nullptr;

    // Extract input data
    cmsColorSpaceSignature colorSpace = static_cast<cmsColorSpaceSignature>(SafeExtractUInt32(data, size, offset));
    cmsFloat64Number inkLimit = SafeExtractDouble(data, size, offset);
    cmsUInt32Number inputFormat = SafeExtractUInt32(data, size, offset);
    cmsUInt32Number outputFormat = SafeExtractUInt32(data, size, offset);
    cmsUInt32Number intent = SafeExtractUInt32(data, size, offset);
    cmsUInt32Number proofingIntent = SafeExtractUInt32(data, size, offset);
    cmsUInt32Number flags = SafeExtractUInt32(data, size, offset);

    // Extract profiles
    for (int i = 0; i < 4; ++i) {
        profiles[i] = SafeExtractProfile(data, size, offset);
    }

    // Create an ink limiting device link profile
    cmsHPROFILE inkLimitingProfile = cmsCreateInkLimitingDeviceLink(colorSpace, inkLimit);
    if (!inkLimitingProfile) {
        return 0; // Handle error
    }

    // Create a proofing transform
    transform = cmsCreateProofingTransform(profiles[0], inputFormat, profiles[1], outputFormat, profiles[2], intent, proofingIntent, flags);
    if (!transform) {
        cmsCloseProfile(inkLimitingProfile);
        return 0; // Handle error
    }
    cmsDeleteTransform(transform);

    // Create a multiprofile transform
    transform = cmsCreateMultiprofileTransform(profiles, 4, inputFormat, outputFormat, intent, flags);
    if (!transform) {
        cmsCloseProfile(inkLimitingProfile);
        return 0; // Handle error
    }
    cmsDeleteTransform(transform);

    // Create an extended transform
    cmsBool BPC[4] = {true, true, false, false};
    cmsUInt32Number intents[4] = {intent, intent, INTENT_RELATIVE_COLORIMETRIC, proofingIntent};
    cmsFloat64Number adaptationStates[4] = {1.0, 1.0, 1.0, 1.0};
    transform = cmsCreateExtendedTransform(nullptr, 4, profiles, BPC, intents, adaptationStates, profiles[2], 1, inputFormat, outputFormat, flags);
    if (!transform) {
        cmsCloseProfile(inkLimitingProfile);
        return 0; // Handle error
    }
    cmsDeleteTransform(transform);

    // Clean up
    cmsCloseProfile(inkLimitingProfile);

    return 0;
}
