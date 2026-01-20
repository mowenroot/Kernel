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
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsHPROFILE hDeviceLink = nullptr;
    cmsCIExyY whitePoint;
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t buffer[256] = {0};
    cmsUInt32Number bufferSize = sizeof(buffer) / sizeof(buffer[0]);

    // Extract data from fuzz input
    memcpy(&whitePoint, data, sizeof(whitePoint));
    safe_strncpy(languageCode, data + sizeof(whitePoint), 2);
    safe_strncpy(countryCode, data + sizeof(whitePoint) + 2, 2);

    // Create a Lab4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) return 0;

    // Check if the profile is a CLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, 0, LCMS_USED_AS_INPUT);

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Create an ink limiting device link
    hDeviceLink = cmsCreateInkLimitingDeviceLinkTHR(nullptr, cmsSigCmykData, 100.0);
    if (!hDeviceLink) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Get profile information
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, bufferSize);

    // Clean up resources
    cmsCloseProfile(hProfile);
    cmsCloseProfile(hDeviceLink);

    return 0;
}
