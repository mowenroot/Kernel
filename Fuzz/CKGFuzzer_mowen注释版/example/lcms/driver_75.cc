#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzzer input to cmsUInt32Number
cmsUInt32Number safe_convert_to_cmsUInt32Number(const uint8_t* data, size_t size, size_t index) {
    if (index >= size) return 0;
    return static_cast<cmsUInt32Number>(data[index]);
}

// Function to safely convert fuzzer input to cmsFloat64Number
cmsFloat64Number safe_convert_to_cmsFloat64Number(const uint8_t* data, size_t size, size_t index) {
    if (index + sizeof(cmsFloat64Number) > size) return 0.0;
    cmsFloat64Number value;
    memcpy(&value, data + index, sizeof(cmsFloat64Number));
    return value;
}

// Function to safely convert fuzzer input to wchar_t buffer
void safe_convert_to_wchar_t(const uint8_t* data, size_t size, size_t index, wchar_t* buffer, size_t buffer_size) {
    if (index + buffer_size * sizeof(wchar_t) > size) return;
    memcpy(buffer, data + index, buffer_size * sizeof(wchar_t));
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    cmsUInt32Number Intent = safe_convert_to_cmsUInt32Number(data, size, 0);
    cmsUInt32Number UsedDirection = safe_convert_to_cmsUInt32Number(data, size, 1);
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);

    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    cmsUnregisterPluginsTHR(NULL);

    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2);
    if (toneCurve) {
        cmsFloat64Number lambda = safe_convert_to_cmsFloat64Number(data, size, 2);
        cmsBool isSmoothed = cmsSmoothToneCurve(toneCurve, lambda);
        cmsFreeToneCurve(toneCurve);
    }

    wchar_t buffer[256] = {0};
    const char LanguageCode[3] = "en";
    const char CountryCode[3] = "US";
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
