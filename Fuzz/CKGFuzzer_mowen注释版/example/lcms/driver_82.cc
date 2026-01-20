#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int32_t extractInt(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(int32_t) > size) {
        return -1; // Invalid input
    }
    int32_t value = *reinterpret_cast<const int32_t*>(data + offset);
    offset += sizeof(int32_t);
    return value;
}

// Function to safely extract a double from the fuzz input
double extractDouble(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(double) > size) {
        return -1.0; // Invalid input
    }
    double value = *reinterpret_cast<const double*>(data + offset);
    offset += sizeof(double);
    return value;
}

// Function to safely extract a boolean from the fuzz input
bool extractBool(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(bool) > size) {
        return false; // Invalid input
    }
    bool value = *reinterpret_cast<const bool*>(data + offset);
    offset += sizeof(bool);
    return value;
}

// Function to safely extract a profile handle from the fuzz input
cmsHPROFILE extractProfile(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(cmsHPROFILE) > size) {
        return nullptr; // Invalid input
    }
    cmsHPROFILE value = *reinterpret_cast<const cmsHPROFILE*>(data + offset);
    offset += sizeof(cmsHPROFILE);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(int32_t) * 2 + sizeof(double) + sizeof(bool) + sizeof(cmsHPROFILE) * 5) {
        return 0;
    }

    size_t offset = 0;

    // Extract parameters from the fuzz input
    int32_t nProfiles = extractInt(data, size, offset, size);
    int32_t InputFormat = extractInt(data, size, offset, size);
    int32_t OutputFormat = extractInt(data, size, offset, size);
    int32_t Intent = extractInt(data, size, offset, size);
    int32_t dwFlags = extractInt(data, size, offset, size);
    double Limit = extractDouble(data, size, offset, size);
    bool BPC = extractBool(data, size, offset, size);
    int32_t nGamutPCSposition = extractInt(data, size, offset, size);

    // Extract profile handles
    cmsHPROFILE hProfiles[5];
    for (int i = 0; i < 5; ++i) {
        hProfiles[i] = extractProfile(data, size, offset, size);
    }

    // Create a multiprofile transform
    cmsHTRANSFORM multiprofileTransform = cmsCreateMultiprofileTransform(hProfiles, nProfiles, InputFormat, OutputFormat, Intent, dwFlags);
    if (multiprofileTransform) {
        cmsDeleteTransform(multiprofileTransform);
    }

    // Create a proofing transform
    cmsHTRANSFORM proofingTransform = cmsCreateProofingTransform(hProfiles[0], InputFormat, hProfiles[1], OutputFormat, hProfiles[2], Intent, Intent, dwFlags);
    if (proofingTransform) {
        cmsDeleteTransform(proofingTransform);
    }

    // Create an ink limiting device link
    cmsHPROFILE inkLimitingProfile = cmsCreateInkLimitingDeviceLink(cmsSigRgbData, Limit);
    if (inkLimitingProfile) {
        cmsCloseProfile(inkLimitingProfile);
    }

    // Create a transform
    cmsHTRANSFORM transform = cmsCreateTransform(hProfiles[0], InputFormat, hProfiles[1], OutputFormat, Intent, dwFlags);
    if (transform) {
        cmsDeleteTransform(transform);
    }

    // Create an extended transform
    cmsBool BPCArray[5] = {BPC, BPC, BPC, BPC, BPC};
    cmsUInt32Number Intents[5] = {static_cast<cmsUInt32Number>(Intent), static_cast<cmsUInt32Number>(Intent), static_cast<cmsUInt32Number>(Intent), static_cast<cmsUInt32Number>(Intent), static_cast<cmsUInt32Number>(Intent)};
    cmsFloat64Number AdaptationStates[5] = {1.0, 1.0, 1.0, 1.0, 1.0};
    cmsHTRANSFORM extendedTransform = cmsCreateExtendedTransform(NULL, 5, hProfiles, BPCArray, Intents, AdaptationStates, hProfiles[3], nGamutPCSposition, InputFormat, OutputFormat, dwFlags);
    if (extendedTransform) {
        cmsDeleteTransform(extendedTransform);
    }

    return 0;
}
