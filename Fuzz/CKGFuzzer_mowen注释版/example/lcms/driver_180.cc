#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract an integer from the fuzz input
int32_t SafeExtractInt(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(int32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = *reinterpret_cast<const int32_t*>(data + offset);
    offset += sizeof(int32_t);
    return value;
}

// Function to safely extract a double from the fuzz input
double SafeExtractDouble(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Return a default value if not enough data
    }
    double value = *reinterpret_cast<const double*>(data + offset);
    offset += sizeof(double);
    return value;
}

// Function to safely extract a boolean from the fuzz input
bool SafeExtractBool(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(bool) > size) {
        return false; // Return a default value if not enough data
    }
    bool value = *reinterpret_cast<const bool*>(data + offset);
    offset += sizeof(bool);
    return value;
}

// Function to safely extract a profile handle from the fuzz input
cmsHPROFILE SafeExtractProfile(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(cmsHPROFILE) > size) {
        return nullptr; // Return a default value if not enough data
    }
    cmsHPROFILE value = *reinterpret_cast<const cmsHPROFILE*>(data + offset);
    offset += sizeof(cmsHPROFILE);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int32_t) * 2 + sizeof(double) + sizeof(cmsHPROFILE) * 3 + sizeof(cmsUInt32Number) * 4 + sizeof(cmsBool) + sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    size_t offset = 0;

    // Extract parameters from fuzz input
    cmsColorSpaceSignature colorSpace = static_cast<cmsColorSpaceSignature>(SafeExtractInt(data, size, offset, size));
    cmsFloat64Number limit = SafeExtractDouble(data, size, offset, size);
    cmsHPROFILE inputProfile = SafeExtractProfile(data, size, offset, size);
    cmsUInt32Number inputFormat = static_cast<cmsUInt32Number>(SafeExtractInt(data, size, offset, size));
    cmsHPROFILE outputProfile = SafeExtractProfile(data, size, offset, size);
    cmsUInt32Number outputFormat = static_cast<cmsUInt32Number>(SafeExtractInt(data, size, offset, size));
    cmsHPROFILE proofingProfile = SafeExtractProfile(data, size, offset, size);
    cmsUInt32Number nIntent = static_cast<cmsUInt32Number>(SafeExtractInt(data, size, offset, size));
    cmsUInt32Number proofingIntent = static_cast<cmsUInt32Number>(SafeExtractInt(data, size, offset, size));
    cmsUInt32Number dwFlags = static_cast<cmsUInt32Number>(SafeExtractInt(data, size, offset, size));
    cmsHPROFILE hProfiles[2] = {inputProfile, outputProfile};
    cmsUInt32Number nProfiles = 2;
    cmsBool BPC = SafeExtractBool(data, size, offset, size);
    cmsUInt32Number intents[2] = {nIntent, proofingIntent};
    cmsFloat64Number adaptationStates[2] = {1.0, 1.0};
    cmsHPROFILE hGamutProfile = SafeExtractProfile(data, size, offset, size);
    cmsUInt32Number nGamutPCSposition = static_cast<cmsUInt32Number>(SafeExtractInt(data, size, offset, size));

    // Create profiles and transforms
    cmsHPROFILE inkLimitingProfile = cmsCreateInkLimitingDeviceLink(colorSpace, limit);
    if (!inkLimitingProfile) {
        return 0; // Handle error
    }

    cmsHTRANSFORM proofingTransform = cmsCreateProofingTransform(inputProfile, inputFormat, outputProfile, outputFormat, proofingProfile, nIntent, proofingIntent, dwFlags);
    if (!proofingTransform) {
        cmsCloseProfile(inkLimitingProfile);
        return 0; // Handle error
    }

    cmsHTRANSFORM multiProfileTransform = cmsCreateMultiprofileTransform(hProfiles, nProfiles, inputFormat, outputFormat, nIntent, dwFlags);
    if (!multiProfileTransform) {
        cmsDeleteTransform(proofingTransform);
        cmsCloseProfile(inkLimitingProfile);
        return 0; // Handle error
    }

    cmsToneCurve* transferFunctions[2] = {nullptr, nullptr};
    cmsHPROFILE linearizationProfile = cmsCreateLinearizationDeviceLink(colorSpace, transferFunctions);
    if (!linearizationProfile) {
        cmsDeleteTransform(multiProfileTransform);
        cmsDeleteTransform(proofingTransform);
        cmsCloseProfile(inkLimitingProfile);
        return 0; // Handle error
    }

    cmsHTRANSFORM extendedTransform = cmsCreateExtendedTransform(nullptr, nProfiles, hProfiles, &BPC, intents, adaptationStates, hGamutProfile, nGamutPCSposition, inputFormat, outputFormat, dwFlags);
    if (!extendedTransform) {
        cmsCloseProfile(linearizationProfile);
        cmsDeleteTransform(multiProfileTransform);
        cmsDeleteTransform(proofingTransform);
        cmsCloseProfile(inkLimitingProfile);
        return 0; // Handle error
    }

    // Clean up resources
    cmsDeleteTransform(extendedTransform);
    cmsCloseProfile(linearizationProfile);
    cmsDeleteTransform(multiProfileTransform);
    cmsDeleteTransform(proofingTransform);
    cmsCloseProfile(inkLimitingProfile);

    return 0;
}
