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
    size_t len = size / sizeof(wchar_t) < max_len ? size / sizeof(wchar_t) : max_len - 1;
    memcpy(dest, src, len * sizeof(wchar_t));
    dest[len] = L'\0';
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the minimum required input
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsCIExyY whitePoint = {0.0, 0.0, 0.0};
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t buffer[256] = {0};
    cmsUInt32Number intent = data[0];
    cmsUInt32Number usedDirection = data[1];

    // Extract white point values from fuzz input
    whitePoint.x = *reinterpret_cast<const double*>(data + 2);
    whitePoint.y = *reinterpret_cast<const double*>(data + 10);

    // Extract language and country codes from fuzz input
    safe_strncpy(languageCode, data + 18, 2, sizeof(languageCode));
    safe_strncpy(countryCode, data + 20, 2, sizeof(countryCode));

    // Create a Lab profile
    hProfile = cmsCreateLab2ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) return 0;

    // Check if the intent is supported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Get the number of tags in the profile
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);

    // Get profile information
    cmsUInt32Number infoLength = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
