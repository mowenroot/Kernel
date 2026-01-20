#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert uint8_t array to uint32_t
uint32_t safe_convert_to_uint32(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if out of bounds
    }
    return *reinterpret_cast<const uint32_t*>(data + offset);
}

// Function to safely convert uint8_t array to cmsCIEXYZ
void safe_convert_to_cmsCIEXYZ(const uint8_t* data, size_t size, size_t offset, cmsCIEXYZ* out) {
    if (offset + sizeof(cmsCIEXYZ) > size) {
        memset(out, 0, sizeof(cmsCIEXYZ)); // Initialize to zero if out of bounds
        return;
    }
    memcpy(out, data + offset, sizeof(cmsCIEXYZ));
}

// Function to safely convert uint8_t array to char[3]
void safe_convert_to_char3(const uint8_t* data, size_t size, size_t offset, char* out) {
    if (offset + 3 > size) {
        memset(out, 0, 3); // Initialize to zero if out of bounds
        return;
    }
    memcpy(out, data + offset, 3);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure data is not NULL and size is non-zero
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0; // Failed to create profile placeholder
    }

    // Set header manufacturer
    uint32_t manufacturer = safe_convert_to_uint32(data, size, 0);
    cmsSetHeaderManufacturer(hProfile, manufacturer);

    // Detect black point
    cmsCIEXYZ blackPoint;
    safe_convert_to_cmsCIEXYZ(data, size, sizeof(uint32_t), &blackPoint);
    uint32_t intent = safe_convert_to_uint32(data, size, sizeof(uint32_t) + sizeof(cmsCIEXYZ));
    uint32_t flags = safe_convert_to_uint32(data, size, sizeof(uint32_t) * 2 + sizeof(cmsCIEXYZ));
    cmsDetectBlackPoint(&blackPoint, hProfile, intent, flags);

    // Get supported intents
    cmsUInt32Number maxIntents = 10;
    cmsUInt32Number intentCodes[10];
    char* intentDescriptions[10];
    cmsGetSupportedIntents(maxIntents, intentCodes, intentDescriptions);

    // Check if tone curve is monotonic
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2);
    if (toneCurve) {
        cmsIsToneCurveMonotonic(toneCurve);
        cmsFreeToneCurve(toneCurve);
    }

    // Get profile info
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    safe_convert_to_char3(data, size, sizeof(uint32_t) * 3 + sizeof(cmsCIEXYZ), languageCode);
    safe_convert_to_char3(data, size, sizeof(uint32_t) * 3 + sizeof(cmsCIEXYZ) + 3, countryCode);
    wchar_t buffer[256];
    cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
