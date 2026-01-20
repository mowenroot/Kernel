#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

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
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsUInt32Number bufferSize = 256;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[bufferSize]);
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    cmsTagSignature tagSig = static_cast<cmsTagSignature>(data[0]);

    // Extract language and country codes from fuzz input
    safe_strncpy(languageCode, data + 1, 2, 3);
    safe_strncpy(countryCode, data + 3, 2, 3);

    // Open profile from memory
    hProfile = cmsOpenProfileFromMem(data + 5, size - 5);
    if (!hProfile) return 0;

    // Read profile information
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer.get(), bufferSize);
    if (infoSize == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Read a tag from the profile
    void* tagData = cmsReadTag(hProfile, tagSig);
    if (!tagData) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Write the tag back to the profile
    if (!cmsWriteTag(hProfile, tagSig, tagData)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Close the profile
    if (!cmsCloseProfile(hProfile)) {
        return 0;
    }

    return 0;
}
