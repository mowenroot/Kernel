#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size, size_t max_size) {
    size_t copy_size = size < max_size ? size : max_size - 1;
    memcpy(dest, src, copy_size);
    dest[copy_size] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size, size_t max_size) {
    size_t copy_size = size < max_size ? size : max_size - 1;
    for (size_t i = 0; i < copy_size; ++i) {
        dest[i] = static_cast<wchar_t>(src[i]);
    }
    dest[copy_size] = L'\0';
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE profile = nullptr;
    cmsUInt32Number intent = data[0];
    cmsUInt32Number direction = data[1];
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t buffer[256] = {0};

    // Extract language and country codes from fuzz input
    safe_strncpy(languageCode, data + 2, 2, sizeof(languageCode));
    safe_strncpy(countryCode, data + 4, 2, sizeof(countryCode));

    // Create an XYZ profile
    profile = cmsCreateXYZProfile();
    if (!profile) return 0;

    // Check if the profile is a CLUT
    cmsBool isCLUT = cmsIsCLUT(profile, intent, direction);

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(profile);

    // Detect TAC (Total Area Coverage)
    cmsFloat64Number tac = cmsDetectTAC(profile);

    // Get profile information
    cmsUInt32Number infoSize = cmsGetProfileInfo(profile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up resources
    cmsCloseProfile(profile);

    return 0;
}
