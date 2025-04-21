#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
const char* SafeStringCopy(const uint8_t* data, size_t size, size_t* offset, size_t max_len) {
    if (*offset + max_len > size) return nullptr;
    const char* str = reinterpret_cast<const char*>(data + *offset);
    *offset += max_len;
    return str;
}

// Function to safely get an integer from fuzz input
cmsUInt32Number SafeGetInt(const uint8_t* data, size_t size, size_t* offset) {
    if (*offset + sizeof(cmsUInt32Number) > size) return 0;
    cmsUInt32Number value = *reinterpret_cast<const cmsUInt32Number*>(data + *offset);
    *offset += sizeof(cmsUInt32Number);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = nullptr;
    cmsHTRANSFORM hTransform = nullptr;
    cmsContext contextID = nullptr;
    cmsUInt32Number intent = 0;
    cmsUInt32Number direction = 0;
    const char* languageCode = nullptr;
    const char* countryCode = nullptr;
    wchar_t buffer[256] = {0};

    // Create a Lab 4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, nullptr);
    if (!hProfile) return 0;

    // Get intent and direction from fuzz input
    intent = SafeGetInt(data, size, &offset);
    direction = SafeGetInt(data, size, &offset);

    // Check if the intent is supported
    if (cmsIsIntentSupported(hProfile, intent, direction)) {
        // Get the transform context ID
        hTransform = reinterpret_cast<cmsHTRANSFORM>(cmsCreateTransform(hProfile, TYPE_Lab_DBL, hProfile, TYPE_Lab_DBL, intent, 0));
        if (hTransform) {
            contextID = cmsGetTransformContextID(hTransform);
            cmsDeleteTransform(hTransform);
        }
    }

    // Get profile info
    languageCode = SafeStringCopy(data, size, &offset, 3);
    countryCode = SafeStringCopy(data, size, &offset, 3);
    if (languageCode && countryCode) {
        cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));
    }

    // Clean up
    if (hProfile) cmsCloseProfile(hProfile);

    return 0;
}
