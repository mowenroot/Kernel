#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzzer input to a cmsUInt32Number
cmsUInt32Number SafeConvertToUInt32(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(cmsUInt32Number) > size) {
        return 0; // Default value if not enough data
    }
    return *reinterpret_cast<const cmsUInt32Number*>(data + offset);
}

// Function to safely convert fuzzer input to a double
double SafeConvertToDouble(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Default value if not enough data
    }
    return *reinterpret_cast<const double*>(data + offset);
}

// Function to safely convert fuzzer input to a wchar_t buffer
void SafeConvertToWCharBuffer(const uint8_t* data, size_t size, size_t offset, wchar_t* buffer, size_t bufferSize) {
    if (offset + bufferSize * sizeof(wchar_t) > size) {
        memset(buffer, 0, bufferSize * sizeof(wchar_t)); // Clear buffer if not enough data
        return;
    }
    memcpy(buffer, data + offset, bufferSize * sizeof(wchar_t));
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < sizeof(cmsUInt32Number) * 2 + sizeof(double) * 4 + 6) {
        return 0;
    }

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0;
    }

    // Use cmsSetHeaderFlags
    cmsUInt32Number flags = SafeConvertToUInt32(data, size, 0);
    cmsSetHeaderFlags(hProfile, flags);

    // Use cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Use cmsDesaturateLab
    cmsCIELab lab;
    lab.L = SafeConvertToDouble(data, size, sizeof(cmsUInt32Number));
    lab.a = SafeConvertToDouble(data, size, sizeof(cmsUInt32Number) + sizeof(double));
    lab.b = SafeConvertToDouble(data, size, sizeof(cmsUInt32Number) + sizeof(double) * 2);
    double amax = SafeConvertToDouble(data, size, sizeof(cmsUInt32Number) + sizeof(double) * 3);
    double amin = SafeConvertToDouble(data, size, sizeof(cmsUInt32Number) + sizeof(double) * 4);
    double bmax = SafeConvertToDouble(data, size, sizeof(cmsUInt32Number) + sizeof(double) * 5);
    double bmin = SafeConvertToDouble(data, size, sizeof(cmsUInt32Number) + sizeof(double) * 6);
    cmsBool desaturated = cmsDesaturateLab(&lab, amax, amin, bmax, bmin);

    // Use cmsDetectTAC
    cmsFloat64Number tac = cmsDetectTAC(hProfile);

    // Use cmsGetProfileInfo
    wchar_t infoBuffer[256];
    const char languageCode[3] = "en";
    const char countryCode[3] = "US";
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, infoBuffer, sizeof(infoBuffer) / sizeof(wchar_t));

    // Clean up resources
    cmsCloseProfile(hProfile);

    return 0;
}
