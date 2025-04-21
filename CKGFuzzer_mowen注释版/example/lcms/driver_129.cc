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
    cmsHTRANSFORM hTransform = nullptr;
    cmsUInt32Number intent = data[0];
    cmsUInt32Number direction = data[1];
    cmsUInt32Number inputFormat = *(cmsUInt32Number*)(data + 2);
    cmsUInt32Number outputFormat = *(cmsUInt32Number*)(data + 6);
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t buffer[256] = {0};

    // Extract language and country codes
    safe_strncpy(languageCode, data + 10, 2, 3);
    safe_strncpy(countryCode, data + 12, 2, 3);

    // Create a Lab4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, nullptr);
    if (!hProfile) return 0;

    // Check if the profile supports the given intent and direction
    cmsBool isCLUTSupported = cmsIsCLUT(hProfile, intent, direction);

    // Detect TAC for the profile
    cmsFloat64Number tac = cmsDetectTAC(hProfile);

    // Get profile information
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Create a transform to change buffer formats
    hTransform = cmsCreateTransformTHR(nullptr, hProfile, TYPE_Lab_16, hProfile, TYPE_Lab_16, INTENT_PERCEPTUAL, cmsFLAGS_NOOPTIMIZE | cmsFLAGS_NOCACHE);
    if (hTransform) {
        cmsBool formatChanged = cmsChangeBuffersFormat(hTransform, inputFormat, outputFormat);
        if (!formatChanged) {
            cmsDeleteTransform(hTransform);
            hTransform = nullptr;
        }
    }

    // Clean up resources
    if (hTransform) cmsDeleteTransform(hTransform);
    if (hProfile) cmsCloseProfile(hProfile);

    return 0;
}
