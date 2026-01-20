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
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // Extract inputs from fuzz data
    cmsUInt32Number Intent = static_cast<cmsUInt32Number>(data[0]);
    cmsUInt32Number UsedDirection = static_cast<cmsUInt32Number>(data[1]);
    cmsUInt32Number model = static_cast<cmsUInt32Number>(data[2]);
    cmsInfoType Info = static_cast<cmsInfoType>(data[3]);

    // Extract language and country codes
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_strncpy(LanguageCode, data + 4, 2, sizeof(LanguageCode));
    safe_strncpy(CountryCode, data + 6, 2, sizeof(CountryCode));

    // Extract buffer for profile info
    wchar_t Buffer[256] = {0};
    size_t buffer_size = sizeof(Buffer) / sizeof(Buffer[0]);

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);
    if (isIntentSupported == FALSE) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);
    if (isCLUT == FALSE) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsSetHeaderModel
    cmsSetHeaderModel(hProfile, model);

    // Call cmsDetectTAC
    cmsFloat64Number TAC = cmsDetectTAC(hProfile);
    if (TAC < 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoLength = cmsGetProfileInfo(hProfile, Info, LanguageCode, CountryCode, Buffer, buffer_size);
    if (infoLength == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Clean up
    cmsCloseProfile(hProfile);
    return 0;
}
