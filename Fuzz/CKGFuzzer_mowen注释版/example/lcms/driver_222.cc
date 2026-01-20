#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t dest_size) {
    size_t i;
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t dest_size) {
    size_t i;
    for (i = 0; i < dest_size - 1 && src[i] != '\0'; ++i) {
        dest[i] = src[i];
    }
    dest[i] = L'\0';
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    cmsUInt16Number alarmCodes[cmsMAXCHANNELS] = {0};
    wchar_t profileInfoBuffer[256] = {0};
    char languageCode[3] = {0};
    char countryCode[3] = {0};

    // Extract data for API inputs
    int tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Ensure we have enough data for the tag index
    if (size < 20) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract tag index from fuzz input
    cmsUInt32Number tagIndex = data[16];
    if (tagIndex >= (cmsUInt32Number)tagCount) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Get tag signature
    cmsTagSignature tagSignature = cmsGetTagSignature(hProfile, tagIndex);
    if (tagSignature == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Get alarm codes
    cmsGetAlarmCodesTHR(NULL, alarmCodes);

    // Ensure we have enough data for language and country codes
    if (size < 26) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract language and country codes from fuzz input
    safe_strncpy(languageCode, data + 20, 3);
    safe_strncpy(countryCode, data + 23, 3);

    // Get profile info
    cmsUInt32Number profileInfoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));
    if (profileInfoSize == 0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Ensure we have enough data for tone curve
    if (size < 32) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Create a tone curve from fuzz input
    cmsToneCurve* toneCurve = cmsBuildTabulatedToneCurve16(NULL, 256, (cmsUInt16Number*)(data + 26));
    if (!toneCurve) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Check if tone curve is monotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);

    // Clean up
    cmsFreeToneCurve(toneCurve);
    cmsCloseProfile(hProfile);

    return 0;
}
