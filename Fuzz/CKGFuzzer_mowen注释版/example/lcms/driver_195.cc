#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size) {
    size_t i;
    for (i = 0; i < size && src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size) {
    size_t i;
    for (i = 0; i < size && src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    dest[i] = L'\0';
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for all operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsCIEXYZ blackPoint;
    wchar_t profileInfoBuffer[256];
    char languageCode[3] = {0};
    char countryCode[3] = {0};

    // Extract language and country codes from fuzz input
    safe_strncpy(languageCode, data, 2);
    safe_strncpy(countryCode, data + 2, 2);

    // Create a NULL profile
    hProfile = cmsCreateNULLProfile();
    if (!hProfile) return 0;

    // Check if the profile is a CLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, data[4], data[5]);

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Detect black point
    cmsBool blackPointDetected = cmsDetectBlackPoint(&blackPoint, hProfile, data[6], data[7]);

    // Get profile information
    cmsUInt32Number profileInfoSize = cmsGetProfileInfo(hProfile, static_cast<cmsInfoType>(data[8]), languageCode, countryCode, profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));

    // Clean up resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
