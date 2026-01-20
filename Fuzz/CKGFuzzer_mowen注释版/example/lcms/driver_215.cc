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

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for all operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsCIExyY whitePoint = {0.0, 0.0, 0.0};
    cmsUInt32Number intent = data[0];
    cmsUInt32Number usedDirection = data[1];
    cmsFloat32Number toneCurveValue = *reinterpret_cast<const cmsFloat32Number*>(data + 2);
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t buffer[256] = {0};

    // Extract language and country codes
    safe_strncpy(languageCode, data + 6, 2, 3);
    safe_strncpy(countryCode, data + 8, 2, 3);

    // Create a Lab profile
    hProfile = cmsCreateLab2ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) return 0;

    // Check if the intent is supported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);

    // Check if the profile uses CLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, usedDirection);

    // Evaluate tone curve
    cmsFloat32Number toneCurveResult = cmsEvalToneCurveFloat(nullptr, toneCurveValue);

    // Get profile information
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
