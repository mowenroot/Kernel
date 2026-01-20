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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the minimum required input
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsCIExyY whitePoint = {0.0, 0.0, 0.0};
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t buffer[256] = {0};
    cmsUInt32Number manufacturer = 0;
    cmsBool isCLUT = FALSE;
    cmsBool isMatrixShaper = FALSE;
    cmsUInt32Number profileInfoSize = 0;

    // Extract data from fuzz input
    whitePoint.x = *reinterpret_cast<const double*>(data);
    whitePoint.y = *reinterpret_cast<const double*>(data + 8);
    whitePoint.Y = *reinterpret_cast<const double*>(data + 16);
    safe_strncpy(languageCode, data + 24, 2, 3);
    safe_strncpy(countryCode, data + 26, 2, 3);

    // Create a Lab 4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) return 0;

    // Check if the profile supports a specific rendering intent
    isCLUT = cmsIsCLUT(hProfile, 0, LCMS_USED_AS_INPUT);

    // Check if the profile is a matrix shaper
    isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Get the manufacturer identifier
    manufacturer = cmsGetHeaderManufacturer(hProfile);

    // Get profile information
    profileInfoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
