#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <algorithm> // Include for std::min

// Function to safely copy a string from fuzz input
const wchar_t* SafeWcsndup(const uint8_t* data, size_t size, size_t max_len) {
    if (size == 0 || max_len == 0) return nullptr;
    size_t len = std::min(size, max_len); // Use std::min from <algorithm>
    wchar_t* str = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
    if (!str) return nullptr;
    memcpy(str, data, len * sizeof(wchar_t));
    str[len] = L'\0';
    return str;
}

// Function to safely get a substring from fuzz input
const char* SafeStrndup(const uint8_t* data, size_t size, size_t max_len) {
    if (size == 0 || max_len == 0) return nullptr;
    size_t len = std::min(size, max_len); // Use std::min from <algorithm>
    char* str = (char*)malloc((len + 1) * sizeof(char));
    if (!str) return nullptr;
    memcpy(str, data, len);
    str[len] = '\0';
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    cmsHANDLE hDict = cmsDictAlloc(0);
    if (!hDict) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract inputs from fuzz data
    cmsUInt32Number Intent = data[0];
    cmsUInt32Number UsedDirection = data[1];
    const char* LanguageCode = SafeStrndup(data + 2, size - 2, 3);
    const char* CountryCode = SafeStrndup(data + 5, size - 5, 3);
    const wchar_t* Name = SafeWcsndup(data + 8, size - 8, 16);
    const wchar_t* Value = SafeWcsndup(data + 24, size - 24, 16);

    // Check if the profile supports the intent and direction
    cmsBool isCLUTSupported = cmsIsCLUT(hProfile, Intent, UsedDirection);

    // Add an entry to the dictionary
    if (Name && Value) {
        cmsBool entryAdded = cmsDictAddEntry(hDict, Name, Value, nullptr, nullptr);
        if (!entryAdded) {
            free((void*)Name);
            free((void*)Value);
            cmsDictFree(hDict);
            cmsCloseProfile(hProfile);
            return 0;
        }
    }

    // Get profile information
    wchar_t buffer[256];
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up
    free((void*)Name);
    free((void*)Value);
    free((void*)LanguageCode);
    free((void*)CountryCode);
    cmsDictFree(hDict);
    cmsCloseProfile(hProfile);

    return 0;
}
