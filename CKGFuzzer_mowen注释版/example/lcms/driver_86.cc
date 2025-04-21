#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <string> // Include this header to resolve std::string errors
#include <algorithm> // Include this header to resolve std::min errors

// Function to safely convert fuzzer input to a string
std::string SafeStringFromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0) return "";
    size_t len = std::min(size, static_cast<size_t>(255)); // Limit to 255 characters
    return std::string(reinterpret_cast<const char*>(data), len);
}

// Function to safely convert fuzzer input to a double
double SafeDoubleFromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    size_t len = std::min(size, static_cast<size_t>(sizeof(double)));
    double value = 0.0;
    memcpy(&value, data, len);
    return value;
}

// Function to safely convert fuzzer input to a uint32_t
cmsUInt32Number SafeUInt32FromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    size_t len = std::min(size, static_cast<size_t>(sizeof(cmsUInt32Number)));
    cmsUInt32Number value = 0;
    memcpy(&value, data, len);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsHPROFILE profile = nullptr;
    cmsCIEXYZ blackPoint;
    cmsToneCurve* toneCurve = nullptr;
    wchar_t infoBuffer[256];
    std::string languageCode, countryCode;
    cmsUInt32Number intent, flags, infoType;
    double lambda;

    // Ensure proper initialization
    memset(&blackPoint, 0, sizeof(blackPoint));
    memset(infoBuffer, 0, sizeof(infoBuffer));

    // Derive inputs from fuzzer data
    languageCode = SafeStringFromFuzzInput(data, size);
    countryCode = SafeStringFromFuzzInput(data + languageCode.size(), size - languageCode.size());
    intent = SafeUInt32FromFuzzInput(data + languageCode.size() + countryCode.size(), size - languageCode.size() - countryCode.size());
    flags = SafeUInt32FromFuzzInput(data + languageCode.size() + countryCode.size() + sizeof(intent), size - languageCode.size() - countryCode.size() - sizeof(intent));
    infoType = SafeUInt32FromFuzzInput(data + languageCode.size() + countryCode.size() + sizeof(intent) + sizeof(flags), size - languageCode.size() - countryCode.size() - sizeof(intent) - sizeof(flags));
    lambda = SafeDoubleFromFuzzInput(data + languageCode.size() + countryCode.size() + sizeof(intent) + sizeof(flags) + sizeof(infoType), size - languageCode.size() - countryCode.size() - sizeof(intent) - sizeof(flags) - sizeof(infoType));

    // Create sRGB profile
    profile = cmsCreate_sRGBProfileTHR(nullptr);
    if (!profile) {
        return 0; // Early exit if profile creation fails
    }

    // Test cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(profile);

    // Test cmsDetectDestinationBlackPoint
    cmsBool blackPointDetected = cmsDetectDestinationBlackPoint(&blackPoint, profile, intent, flags);

    // Create and smooth tone curve
    toneCurve = cmsBuildGamma(nullptr, 2.2);
    if (toneCurve) {
        cmsBool toneCurveSmoothed = cmsSmoothToneCurve(toneCurve, lambda);
        cmsFreeToneCurve(toneCurve);
    }

    // Test cmsGetProfileInfo
    cmsUInt32Number infoLength = cmsGetProfileInfo(profile, static_cast<cmsInfoType>(infoType), languageCode.c_str(), countryCode.c_str(), infoBuffer, sizeof(infoBuffer) / sizeof(infoBuffer[0]));

    // Clean up
    cmsCloseProfile(profile);

    return 0; // Non-zero return values are reserved for future use.
}
