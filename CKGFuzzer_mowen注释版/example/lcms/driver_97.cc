#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <algorithm> // Include for std::min

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = std::min(size, max_len - 1); // Use std::min from <algorithm>
    memcpy(dest, src, len);
    dest[len] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = std::min(size, max_len - 1); // Use std::min from <algorithm>
    for (size_t i = 0; i < len; ++i) {
        dest[i] = static_cast<wchar_t>(src[i]);
    }
    dest[len] = L'\0';
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the minimum required inputs
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    std::unique_ptr<wchar_t[]> profileInfoBuffer(new wchar_t[256]);
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    cmsUInt32Number intent = data[0];
    cmsUInt32Number usedDirection = data[1];
    cmsFloat32Number toneCurveValue = *reinterpret_cast<const cmsFloat32Number*>(data + 2);

    // Extract language and country codes
    safe_strncpy(languageCode, data + 6, 2, sizeof(languageCode));
    safe_strncpy(countryCode, data + 8, 2, sizeof(countryCode));

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, usedDirection);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsEvalToneCurveFloat
    cmsToneCurve* toneCurve = cmsBuildGamma(0, 2.2);
    if (toneCurve) {
        cmsFloat32Number evalResult = cmsEvalToneCurveFloat(toneCurve, toneCurveValue);
        cmsFreeToneCurve(toneCurve);
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer.get(), 256);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
