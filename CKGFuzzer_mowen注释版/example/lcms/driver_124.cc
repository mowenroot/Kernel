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

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the minimum required inputs
    if (size < 16) return 0;

    // Create a dummy profile handle for testing
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // Extract inputs from fuzz data
    cmsUInt32Number Intent = *reinterpret_cast<const cmsUInt32Number*>(data + 8);
    cmsUInt32Number UsedDirection = *reinterpret_cast<const cmsUInt32Number*>(data + 12);

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsGetTransformContextID
    cmsContext contextID = cmsGetTransformContextID(reinterpret_cast<cmsHTRANSFORM>(hProfile));

    // Prepare inputs for cmsGetProfileInfo
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    wchar_t Buffer[256] = {0};

    // Ensure we have enough data for language and country codes
    if (size >= 22) {
        safe_strncpy(LanguageCode, data + 16, 2, 3);
        safe_strncpy(CountryCode, data + 18, 2, 3);
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, sizeof(Buffer) / sizeof(wchar_t));

    // Handle potential errors
    if (isIntentSupported == FALSE || isCLUT == FALSE || isMatrixShaper == FALSE || contextID == NULL || infoSize == 0) {
        // Handle error appropriately (e.g., log, return early)
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Ensure all allocated resources are freed
    cmsCloseProfile(hProfile);

    return 0;
}
