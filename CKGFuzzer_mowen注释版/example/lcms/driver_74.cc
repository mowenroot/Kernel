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
    // Ensure we have enough data for the minimum required inputs
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    cmsUInt32Number Intent = data[0];
    cmsUInt32Number UsedDirection = data[1];
    cmsFloat64Number Precision = *reinterpret_cast<const cmsFloat64Number*>(data + 2);

    // Extract language and country codes
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_strncpy(LanguageCode, data + 10, 2, sizeof(LanguageCode));
    safe_strncpy(CountryCode, data + 12, 2, sizeof(CountryCode));

    // Buffer for profile info
    wchar_t Buffer[256] = {0};
    cmsUInt32Number BufferSize = sizeof(Buffer) / sizeof(wchar_t);

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);

    // Call cmsUnregisterPlugins
    cmsUnregisterPlugins();

    // Create a dummy tone curve for cmsEstimateGamma
    cmsToneCurve* t = cmsBuildGamma(NULL, 2.2);
    if (t) {
        cmsFloat64Number gamma = cmsEstimateGamma(t, Precision);
        cmsFreeToneCurve(t);
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, BufferSize);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
