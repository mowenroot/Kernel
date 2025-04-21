#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* SafeStrndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely copy a wide string from fuzz input
wchar_t* SafeWcsndup(const uint8_t* data, size_t size) {
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
    cmsHANDLE hIT8 = cmsIT8Alloc(nullptr); // Pass nullptr as ContextID
    if (!hIT8) return 0;

    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (!hProfile) {
        cmsIT8Free(hIT8);
        return 0;
    }

    // Extract strings from fuzz input
    char* cPatch = SafeStrndup(data, size / 4);
    char* cSample = SafeStrndup(data + size / 4, size / 4);
    char* Val = SafeStrndup(data + size / 2, size / 4);
    char LanguageCode[3] = { 'e', 'n', '\0' };
    char CountryCode[3] = { 'U', 'S', '\0' };
    wchar_t Buffer[256];

    // Ensure all strings are valid
    if (!cPatch || !cSample || !Val) {
        free(cPatch);
        free(cSample);
        free(Val);
        cmsCloseProfile(hProfile);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Call cmsIT8SetData
    if (!cmsIT8SetData(hIT8, cPatch, cSample, Val)) {
        // Handle error
    }

    // Call cmsIsIntentSupported
    cmsUInt32Number Intent = data[size - 4];
    cmsUInt32Number UsedDirection = data[size - 3];
    if (cmsIsIntentSupported(hProfile, Intent, UsedDirection)) {
        // Intent is supported
    }

    // Call cmsIT8SetPropertyStr
    const char* Key = "FuzzKey";
    if (!cmsIT8SetPropertyStr(hIT8, Key, Val)) {
        // Handle error
    }

    // Call cmsIsCLUT
    if (cmsIsCLUT(hProfile, Intent, UsedDirection)) {
        // CLUT is supported
    }

    // Call cmsGetProfileInfo
    if (cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, sizeof(Buffer)) == 0) {
        // Handle error
    }

    // Clean up
    free(cPatch);
    free(cSample);
    free(Val);
    cmsCloseProfile(hProfile);
    cmsIT8Free(hIT8);

    return 0;
}
