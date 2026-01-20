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
    // Ensure we have enough data for basic operations
    if (size < 32) return 0;

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // Use RAII to manage the profile handle
    std::unique_ptr<void, decltype(&cmsCloseProfile)> profile_guard(hProfile, cmsCloseProfile);

    // Extract data for API inputs
    cmsUInt32Number model = static_cast<cmsUInt32Number>(data[0]);
    cmsUInt32Number renderingIntent = static_cast<cmsUInt32Number>(data[1]);
    cmsUInt32Number intent = static_cast<cmsUInt32Number>(data[2]);
    cmsUInt32Number direction = static_cast<cmsUInt32Number>(data[3]);

    // Set profile header model
    cmsSetHeaderModel(hProfile, model);

    // Set profile header rendering intent
    cmsSetHeaderRenderingIntent(hProfile, renderingIntent);

    // Check if the profile supports the given intent and direction
    cmsBool isCLUTSupported = cmsIsCLUT(hProfile, intent, direction);

    // Prepare data for cmsDesaturateLab
    cmsCIELab lab;
    lab.L = static_cast<double>(data[4]);
    lab.a = static_cast<double>(data[5]);
    lab.b = static_cast<double>(data[6]);
    double amax = static_cast<double>(data[7]);
    double amin = static_cast<double>(data[8]);
    double bmax = static_cast<double>(data[9]);
    double bmin = static_cast<double>(data[10]);

    // Desaturate the Lab color
    cmsBool desaturated = cmsDesaturateLab(&lab, amax, amin, bmax, bmin);

    // Prepare data for cmsGetProfileInfo
    char languageCode[3];
    char countryCode[3];
    safe_strncpy(languageCode, data + 11, 2, sizeof(languageCode));
    safe_strncpy(countryCode, data + 13, 2, sizeof(countryCode));

    // Allocate a buffer for the profile info
    const size_t bufferSize = 256;
    std::unique_ptr<wchar_t[]> buffer(new wchar_t[bufferSize]);

    // Get profile info
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer.get(), bufferSize);

    // Ensure all resources are freed and no memory leaks occur
    return 0;
}
