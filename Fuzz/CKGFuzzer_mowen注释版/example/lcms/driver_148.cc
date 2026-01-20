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
    for (size_t i = 0; i < len; ++i) {
        dest[i] = static_cast<wchar_t>(src[i * sizeof(wchar_t)]);
    }
    dest[len] = L'\0';
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the minimum required input
    if (size < 12) return 0;

    // Initialize variables
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) return 0;

    cmsHPROFILE profile = cmsCreateProfilePlaceholder(NULL);
    if (!profile) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Extract language and country codes from fuzz input
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    safe_strncpy(languageCode, data, 2, 3);
    safe_strncpy(countryCode, data + 2, 2, 3);

    // Extract ASCII string from fuzz input
    char asciiString[256] = {0};
    safe_strncpy(asciiString, data + 4, size - 4, 256);

    // Extract wide string from fuzz input
    wchar_t wideString[256] = {0};
    safe_wcsncpy(wideString, data + 4, size - 4, 256);

    // Call cmsMLUsetASCII
    if (!cmsMLUsetASCII(mlu, languageCode, countryCode, asciiString)) {
        cmsCloseProfile(profile);
        cmsMLUfree(mlu);
        return 0;
    }

    // Call cmsMLUgetTranslation
    char obtainedLanguage[3] = {0};
    char obtainedCountry[3] = {0};
    if (!cmsMLUgetTranslation(mlu, languageCode, countryCode, obtainedLanguage, obtainedCountry)) {
        cmsCloseProfile(profile);
        cmsMLUfree(mlu);
        return 0;
    }

    // Call cmsIsMatrixShaper
    if (cmsIsMatrixShaper(profile)) {
        // Handle matrix shaper profile
    }

    // Call cmsMLUsetWide
    if (!cmsMLUsetWide(mlu, languageCode, countryCode, wideString)) {
        cmsCloseProfile(profile);
        cmsMLUfree(mlu);
        return 0;
    }

    // Call cmsGetProfileInfo
    wchar_t profileInfoBuffer[256] = {0};
    cmsUInt32Number profileInfoSize = cmsGetProfileInfo(profile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, 256);
    if (profileInfoSize == 0) {
        cmsCloseProfile(profile);
        cmsMLUfree(mlu);
        return 0;
    }

    // Clean up
    cmsCloseProfile(profile);
    cmsMLUfree(mlu);

    return 0;
}
