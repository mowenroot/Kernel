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
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsUInt32Number Intent = data[0];
    cmsUInt32Number UsedDirection = data[1];
    cmsUInt16Number AlarmCodes[cmsMAXCHANNELS] = {0};
    cmsFloat64Number TAC = 0.0;
    wchar_t ProfileInfoBuffer[256] = {0};
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};

    // Safely copy language and country codes from fuzz input
    safe_strncpy(LanguageCode, data + 2, 2, sizeof(LanguageCode));
    safe_strncpy(CountryCode, data + 4, 2, sizeof(CountryCode));

    // Create a profile handle from fuzz input (assuming data + 6 contains profile data)
    hProfile = cmsOpenProfileFromMem(data + 6, size - 6);
    if (!hProfile) return 0;

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsGetAlarmCodes
    cmsGetAlarmCodes(AlarmCodes);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);

    // Call cmsDetectTAC
    TAC = cmsDetectTAC(hProfile);

    // Call cmsGetProfileInfo
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, ProfileInfoBuffer, sizeof(ProfileInfoBuffer) / sizeof(wchar_t));

    // Clean up resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
