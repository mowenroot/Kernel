#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely convert fuzz input to a string
void safe_str_from_data(char* dest, const uint8_t* data, size_t size) {
    size_t len = size < 3 ? size : 2;
    safe_copy(dest, data, len);
    dest[len] = '\0';
}

// Function to safely convert fuzz input to a double
double safe_double_from_data(const uint8_t* data, size_t size) {
    if (size < sizeof(double)) {
        return 0.0;
    }
    double value;
    safe_copy(&value, data, sizeof(double));
    return value;
}

// Function to safely convert fuzz input to a cmsCIExyY structure
void safe_cmsCIExyY_from_data(cmsCIExyY* dest, const uint8_t* data, size_t size) {
    if (size < sizeof(cmsCIExyY)) {
        dest->x = dest->y = dest->Y = 0.0;
        return;
    }
    safe_copy(dest, data, sizeof(cmsCIExyY));
}

// Function to safely convert fuzz input to a cmsCIEXYZ structure
void safe_cmsCIEXYZ_from_data(cmsCIEXYZ* dest, const uint8_t* data, size_t size) {
    if (size < sizeof(cmsCIEXYZ)) {
        dest->X = dest->Y = dest->Z = 0.0;
        return;
    }
    safe_copy(dest, data, sizeof(cmsCIEXYZ));
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(double) + sizeof(cmsCIExyY) + 3 + 3 + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize variables
    cmsFloat64Number tempK;
    cmsCIExyY whitePoint;
    cmsCIEXYZ blackPoint;
    cmsUInt32Number intent = *reinterpret_cast<const cmsUInt32Number*>(data + size - sizeof(cmsUInt32Number));
    cmsUInt32Number flags = *reinterpret_cast<const cmsUInt32Number*>(data + size - 2 * sizeof(cmsUInt32Number));
    char languageCode[3];
    char countryCode[3];
    wchar_t profileInfoBuffer[256];

    // Extract data from fuzz input
    safe_cmsCIExyY_from_data(&whitePoint, data, sizeof(cmsCIExyY));
    safe_str_from_data(languageCode, data + sizeof(cmsCIExyY), 3);
    safe_str_from_data(countryCode, data + sizeof(cmsCIExyY) + 3, 3);

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0;
    }

    // Call cmsTempFromWhitePoint
    if (!cmsTempFromWhitePoint(&tempK, &whitePoint)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsIsCLUT
    if (!cmsIsCLUT(hProfile, intent, LCMS_USED_AS_INPUT)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsSetHeaderFlags
    cmsSetHeaderFlags(hProfile, flags);

    // Call cmsDetectBlackPoint
    if (!cmsDetectBlackPoint(&blackPoint, hProfile, intent, 0)) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsGetProfileInfo
    cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
