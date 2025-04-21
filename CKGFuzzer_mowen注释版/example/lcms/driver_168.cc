#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzzer input to a cmsColorSpaceSignature
cmsColorSpaceSignature GetColorSpaceFromInput(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsColorSpaceSignature)) {
        return (cmsColorSpaceSignature)0; // Return a default value if input is too small
    }
    return *reinterpret_cast<const cmsColorSpaceSignature*>(data);
}

// Function to safely convert fuzzer input to a cmsTagSignature
cmsTagSignature GetTagSignatureFromInput(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsTagSignature)) {
        return (cmsTagSignature)0; // Return a default value if input is too small
    }
    return *reinterpret_cast<const cmsTagSignature*>(data);
}

// Function to safely convert fuzzer input to a cmsInfoType
cmsInfoType GetInfoTypeFromInput(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsInfoType)) {
        return (cmsInfoType)0; // Return a default value if input is too small
    }
    return *reinterpret_cast<const cmsInfoType*>(data);
}

// Function to safely convert fuzzer input to a cmsUInt32Number
cmsUInt32Number GetUInt32FromInput(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0; // Return a default value if input is too small
    }
    return *reinterpret_cast<const cmsUInt32Number*>(data);
}

// Function to safely convert fuzzer input to a string
void GetStringFromInput(const uint8_t* data, size_t size, char* buffer, size_t bufferSize) {
    if (size < bufferSize) {
        bufferSize = size;
    }
    memcpy(buffer, data, bufferSize);
    buffer[bufferSize - 1] = '\0'; // Ensure null-termination
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input is large enough to be meaningful
    if (size < sizeof(cmsColorSpaceSignature) + sizeof(cmsTagSignature) + sizeof(cmsInfoType) + sizeof(cmsUInt32Number) + 6) {
        return 0;
    }

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Set the color space
    cmsColorSpaceSignature colorSpace = GetColorSpaceFromInput(data, size);
    cmsSetColorSpace(hProfile, colorSpace);

    // Write a tag to the profile
    cmsTagSignature tagSignature = GetTagSignatureFromInput(data + sizeof(cmsColorSpaceSignature), size - sizeof(cmsColorSpaceSignature));
    cmsWriteTag(hProfile, tagSignature, nullptr); // Write a null tag to delete it

    // Get the tag count
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        cmsCloseProfile(hProfile);
        return 0; // Failed to get tag count
    }

    // Get profile info
    cmsInfoType infoType = GetInfoTypeFromInput(data + sizeof(cmsColorSpaceSignature) + sizeof(cmsTagSignature), size - sizeof(cmsColorSpaceSignature) - sizeof(cmsTagSignature));
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    GetStringFromInput(data + sizeof(cmsColorSpaceSignature) + sizeof(cmsTagSignature) + sizeof(cmsInfoType), size - sizeof(cmsColorSpaceSignature) - sizeof(cmsTagSignature) - sizeof(cmsInfoType), languageCode, 3);
    GetStringFromInput(data + sizeof(cmsColorSpaceSignature) + sizeof(cmsTagSignature) + sizeof(cmsInfoType) + 3, size - sizeof(cmsColorSpaceSignature) - sizeof(cmsTagSignature) - sizeof(cmsInfoType) - 3, countryCode, 3);
    wchar_t buffer[256] = {0};
    cmsGetProfileInfo(hProfile, infoType, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(wchar_t));

    // Get supported intents
    cmsUInt32Number maxIntents = GetUInt32FromInput(data + sizeof(cmsColorSpaceSignature) + sizeof(cmsTagSignature) + sizeof(cmsInfoType) + 6, size - sizeof(cmsColorSpaceSignature) - sizeof(cmsTagSignature) - sizeof(cmsInfoType) - 6);
    cmsUInt32Number codes[10];
    char* descriptions[10];
    cmsGetSupportedIntents(maxIntents, codes, descriptions);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
