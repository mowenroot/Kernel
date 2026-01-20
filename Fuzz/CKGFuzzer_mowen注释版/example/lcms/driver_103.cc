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
        dest[i] = static_cast<wchar_t>(src[i]);
    }
    dest[len] = L'\0';
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Create a dummy profile handle for testing
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // Initialize variables
    cmsInt32Number tagCount = 0;
    cmsUInt16Number alarmCodes[cmsMAXCHANNELS] = {0};
    cmsBool isMonotonic = FALSE;
    cmsTagSignature tagSignature = cmsTagSignature(0); // Corrected initialization
    wchar_t profileInfoBuffer[256] = {0};
    char languageCode[3] = {0};
    char countryCode[3] = {0};

    // Extract inputs from fuzz data
    size_t offset = 0;
    tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract language and country codes
    safe_strncpy(languageCode, data + offset, 2, sizeof(languageCode));
    offset += 2;
    safe_strncpy(countryCode, data + offset, 2, sizeof(countryCode));
    offset += 2;

    // Extract tag index
    cmsUInt32Number tagIndex = static_cast<cmsUInt32Number>(data[offset]);
    offset += 1;

    // Get alarm codes
    cmsGetAlarmCodesTHR(NULL, alarmCodes);

    // Get tag signature
    tagSignature = cmsGetTagSignature(hProfile, tagIndex);

    // Get profile info
    cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));

    // Create a dummy tone curve for testing
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2);
    if (toneCurve) {
        isMonotonic = cmsIsToneCurveMonotonic(toneCurve);
        cmsFreeToneCurve(toneCurve);
    }

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
