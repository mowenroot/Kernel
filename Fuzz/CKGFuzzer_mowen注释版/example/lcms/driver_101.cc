#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = strnlen(reinterpret_cast<const char*>(data), size);
    if (len > max_len) len = max_len;
    char* str = static_cast<char*>(malloc(len + 1));
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Function to safely allocate memory for a structure
template <typename T>
T* safe_malloc(size_t size) {
    return static_cast<T*>(malloc(size));
}

// Function to safely free memory
template <typename T>
void safe_free(T* ptr) {
    free(ptr);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsNAMEDCOLORLIST* namedColorList = nullptr;
    cmsCIELab lab = {0.0, 0.0, 0.0};
    cmsFloat64Number tac = 0.0;
    wchar_t* profileInfoBuffer = nullptr;
    char* languageCode = nullptr;
    char* countryCode = nullptr;

    // Extract data for API inputs
    size_t offset = 0;
    cmsUInt32Number intent = data[offset++];
    cmsUInt32Number usedDirection = data[offset++];
    double amax = *reinterpret_cast<const double*>(data + offset); offset += sizeof(double);
    double amin = *reinterpret_cast<const double*>(data + offset); offset += sizeof(double);
    double bmax = *reinterpret_cast<const double*>(data + offset); offset += sizeof(double);
    double bmin = *reinterpret_cast<const double*>(data + offset); offset += sizeof(double);
    lab.L = *reinterpret_cast<const double*>(data + offset); offset += sizeof(double);
    lab.a = *reinterpret_cast<const double*>(data + offset); offset += sizeof(double);
    lab.b = *reinterpret_cast<const double*>(data + offset); offset += sizeof(double);

    // Extract language and country codes
    languageCode = safe_strndup(data + offset, size - offset, 2); offset += 3;
    countryCode = safe_strndup(data + offset, size - offset, 2); offset += 3;

    // Create a profile handle
    hProfile = cmsCreateProfilePlaceholder(0);
    if (!hProfile) return 0;

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);
    if (isIntentSupported) {
        // Handle the case where the intent is supported
    }

    // Call cmsDesaturateLab
    cmsBool desaturated = cmsDesaturateLab(&lab, amax, amin, bmax, bmin);
    if (desaturated) {
        // Handle the case where the color was desaturated
    }

    // Call cmsDetectTAC
    tac = cmsDetectTAC(hProfile);
    if (tac > 0.0) {
        // Handle the case where TAC was detected
    }

    // Allocate buffer for profile info
    profileInfoBuffer = static_cast<wchar_t*>(malloc(1024 * sizeof(wchar_t)));
    if (profileInfoBuffer) {
        // Call cmsGetProfileInfo
        cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, 1024);
        if (infoSize > 0) {
            // Handle the case where profile info was retrieved
        }
        safe_free(profileInfoBuffer);
    }

    // Free the named color list if allocated
    if (namedColorList) {
        cmsFreeNamedColorList(namedColorList);
    }

    // Close the profile handle
    cmsCloseProfile(hProfile);

    // Free allocated strings
    safe_free(languageCode);
    safe_free(countryCode);

    return 0;
}
