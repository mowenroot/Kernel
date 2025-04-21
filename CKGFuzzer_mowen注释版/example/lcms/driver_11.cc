#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <string> // Added to include std::string

// Function to safely convert a uint8_t array to a double
double safe_atod(const uint8_t* data, size_t size) {
    char buffer[32]; // Assuming a reasonable size for the buffer
    size_t len = size < sizeof(buffer) - 1 ? size : sizeof(buffer) - 1;
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    return strtod(buffer, nullptr);
}

// Function to safely convert a uint8_t array to an integer
int safe_atoi(const uint8_t* data, size_t size) {
    char buffer[32]; // Assuming a reasonable size for the buffer
    size_t len = size < sizeof(buffer) - 1 ? size : sizeof(buffer) - 1;
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    return atoi(buffer);
}

// Function to safely convert a uint8_t array to a string
std::string safe_string(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 32) return 0;

    // Initialize variables
    cmsHANDLE hIT8 = cmsIT8Alloc(nullptr);
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(nullptr);
    cmsToneCurve* toneCurve = cmsBuildTabulatedToneCurve16(nullptr, 256, nullptr);
    wchar_t profileInfoBuffer[256];
    char languageCode[3] = "en";
    char countryCode[3] = "US";

    // Ensure proper initialization
    if (!hIT8 || !hProfile || !toneCurve) {
        cmsIT8Free(hIT8);
        cmsCloseProfile(hProfile);
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    // Extract data from fuzz input
    int row = safe_atoi(data, 4);
    int col = safe_atoi(data + 4, 4);
    double lambda = safe_atod(data + 8, 8);
    std::string langCode = safe_string(data + 16, 2);
    std::string countryCodeStr = safe_string(data + 18, 2);
    memcpy(languageCode, langCode.c_str(), 2);
    memcpy(countryCode, countryCodeStr.c_str(), 2);

    // Call cmsIT8GetDataRowColDbl
    cmsFloat64Number dataValue = cmsIT8GetDataRowColDbl(hIT8, row, col);
    if (dataValue == 0.0 && errno == ERANGE) {
        // Handle error
    }

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);
    if (!isMatrixShaper) {
        // Handle error
    }

    // Call cmsSmoothToneCurve
    cmsBool isSmoothed = cmsSmoothToneCurve(toneCurve, lambda);
    if (!isSmoothed) {
        // Handle error
    }

    // Call cmsIsToneCurveMonotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);
    if (!isMonotonic) {
        // Handle error
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number profileInfoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));
    if (profileInfoSize == 0) {
        // Handle error
    }

    // Clean up resources
    cmsIT8Free(hIT8);
    cmsCloseProfile(hProfile);
    cmsFreeToneCurve(toneCurve);

    return 0;
}
