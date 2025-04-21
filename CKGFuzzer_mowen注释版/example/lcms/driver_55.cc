#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely copy a wide string from fuzz input
wchar_t* safe_wcsndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    wchar_t* wstr = (wchar_t*)malloc((size + 1) * sizeof(wchar_t));
    if (!wstr) return nullptr;
    for (size_t i = 0; i < size; ++i) {
        wstr[i] = (wchar_t)data[i];
    }
    wstr[size] = L'\0';
    return wstr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    void* tagData = nullptr;
    char* languageCode = nullptr;
    char* countryCode = nullptr;
    wchar_t* buffer = nullptr;
    cmsUInt32Number bufferSize = 0;

    // Open profile from memory
    hProfile = cmsOpenProfileFromMem(data, size);
    if (!hProfile) return 0;

    // Read a tag from the profile
    cmsTagSignature tagSig = (cmsTagSignature)data[0];
    tagData = cmsReadTag(hProfile, tagSig);
    if (tagData) {
        // Write the tag back to the profile
        if (!cmsWriteTag(hProfile, tagSig, tagData)) {
            // Handle error
        }
    }

    // Check if the profile is a CLUT
    cmsUInt32Number intent = data[1];
    cmsUInt32Number direction = data[2];
    if (cmsIsCLUT(hProfile, intent, direction)) {
        // Handle CLUT profile
    }

    // Get profile information
    languageCode = safe_strndup(data + 3, 3);
    countryCode = safe_strndup(data + 6, 3);
    bufferSize = data[9];
    buffer = (wchar_t*)malloc(bufferSize * sizeof(wchar_t));
    if (languageCode && countryCode && buffer) {
        cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, bufferSize);
    }

    // Clean up
    if (hProfile) cmsCloseProfile(hProfile);
    if (tagData) free(tagData);
    if (languageCode) free(languageCode);
    if (countryCode) free(countryCode);
    if (buffer) free(buffer);

    return 0;
}
