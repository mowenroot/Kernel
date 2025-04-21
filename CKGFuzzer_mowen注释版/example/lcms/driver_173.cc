#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len - 1;
    for (size_t i = 0; i < len; ++i) {
        dest[i] = (wchar_t)src[i];
    }
    dest[len] = L'\0';
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 32) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsTagSignature tagSig = (cmsTagSignature)0;
    cmsInt32Number tagCount = 0;
    cmsUInt32Number infoSize = 0;
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t buffer[256] = {0};
    cmsCIExyY whitePoint = {0.0, 0.0, 0.0};
    cmsUInt8Number profileID[16] = {0};

    // Create a Lab4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) return 0;

    // Set the Profile ID from fuzz input
    memcpy(profileID, data, 16);
    cmsSetHeaderProfileID(hProfile, profileID);

    // Get the tag count
    tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Get a tag signature from fuzz input
    cmsUInt32Number tagIndex = (cmsUInt32Number)(data[16] % (tagCount + 1));
    tagSig = cmsGetTagSignature(hProfile, tagIndex);

    // Get profile info using fuzz input
    safe_strncpy(languageCode, data + 17, 2, 3);
    safe_strncpy(countryCode, data + 19, 2, 3);
    infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
