#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzzer input to a string
const char* SafeStringFromData(const uint8_t* data, size_t size, size_t max_len) {
    static char buffer[256];
    size_t len = size < max_len ? size : max_len;
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    return buffer;
}

// Function to safely convert fuzzer input to a wchar_t string
const wchar_t* SafeWStringFromData(const uint8_t* data, size_t size, size_t max_len) {
    static wchar_t buffer[256];
    size_t len = size < max_len ? size : max_len;
    for (size_t i = 0; i < len; ++i) {
        buffer[i] = static_cast<wchar_t>(data[i]);
    }
    buffer[len] = L'\0';
    return buffer;
}

// Function to safely convert fuzzer input to a cmsUInt32Number
cmsUInt32Number SafeUInt32FromData(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(cmsUInt32Number) > size) {
        return 0;
    }
    return *reinterpret_cast<const cmsUInt32Number*>(data + offset);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsCIEXYZ blackPoint;
    cmsColorSpaceSignature pcs;
    wchar_t profileInfoBuffer[256];
    cmsUInt32Number profileInfoSize = 256;

    // Create a profile from the fuzzer input
    hProfile = cmsOpenProfileFromMem(data, size);
    if (!hProfile) {
        return 0;
    }

    // Use cmsIsCLUT
    cmsUInt32Number intent = SafeUInt32FromData(data, size, 0);
    cmsUInt32Number direction = SafeUInt32FromData(data, size, 4);
    cmsIsCLUT(hProfile, intent, direction);

    // Use cmsIsMatrixShaper
    cmsIsMatrixShaper(hProfile);

    // Use cmsDetectBlackPoint
    cmsUInt32Number blackPointIntent = SafeUInt32FromData(data, size, 8);
    cmsUInt32Number blackPointFlags = SafeUInt32FromData(data, size, 12);
    cmsDetectBlackPoint(&blackPoint, hProfile, blackPointIntent, blackPointFlags);

    // Use cmsGetPCS
    pcs = cmsGetPCS(hProfile);

    // Use cmsGetProfileInfo
    const char* languageCode = SafeStringFromData(data, size, 3);
    const char* countryCode = SafeStringFromData(data, size, 3);
    cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, profileInfoSize);

    // Clean up
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
