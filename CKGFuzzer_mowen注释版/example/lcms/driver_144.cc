#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size) {
    size_t i;
    for (i = 0; i < size && src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size) {
    size_t i;
    for (i = 0; i < size && src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    dest[i] = L'\0';
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsUInt32Number intent = data[0];
    cmsUInt32Number direction = data[1];
    cmsTagSignature tagSig = static_cast<cmsTagSignature>(data[2]);
    cmsTagSignature destSig = static_cast<cmsTagSignature>(data[3]);
    cmsCIExyY whitePoint;
    whitePoint.x = *reinterpret_cast<const float*>(data + 4);
    whitePoint.y = *reinterpret_cast<const float*>(data + 8);
    whitePoint.Y = *reinterpret_cast<const float*>(data + 12);

    // Create a Lab 4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) return 0;

    // Check if the intent is supported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, direction);

    // Link a tag to another tag
    cmsBool isLinked = cmsLinkTag(hProfile, tagSig, destSig);

    // Check if the profile supports CLUT
    cmsBool isCLUTSupported = cmsIsCLUT(hProfile, intent, direction);

    // Get profile information
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    safe_strncpy(languageCode, data + 16, 2);
    safe_strncpy(countryCode, data + 18, 2);

    wchar_t buffer[256] = {0};
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
