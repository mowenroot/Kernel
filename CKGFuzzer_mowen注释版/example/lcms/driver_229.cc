#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a cmsUInt32Number
cmsUInt32Number safe_convert_to_cmsUInt32Number(const uint8_t* data, size_t size, size_t index) {
    if (index >= size) return 0;
    return static_cast<cmsUInt32Number>(data[index]);
}

// Function to safely convert fuzz input to a cmsTagSignature
cmsTagSignature safe_convert_to_cmsTagSignature(const uint8_t* data, size_t size, size_t index) {
    if (index + sizeof(cmsTagSignature) > size) return static_cast<cmsTagSignature>(0);
    return *reinterpret_cast<const cmsTagSignature*>(data + index);
}

// Function to safely convert fuzz input to a string
void safe_convert_to_string(const uint8_t* data, size_t size, size_t index, char* buffer, size_t buffer_size) {
    if (index + buffer_size > size) {
        buffer[0] = '\0';
        return;
    }
    memcpy(buffer, data + index, buffer_size);
    buffer[buffer_size - 1] = '\0';
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // Variables for API inputs
    cmsUInt32Number intent = safe_convert_to_cmsUInt32Number(data, size, 0);
    cmsUInt32Number direction = safe_convert_to_cmsUInt32Number(data, size, 4);
    cmsUInt32Number tagIndex = safe_convert_to_cmsUInt32Number(data, size, 8);
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    safe_convert_to_string(data, size, 12, languageCode, 2);
    safe_convert_to_string(data, size, 14, countryCode, 2);
    wchar_t buffer[256] = {0};

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, direction);
    if (isCLUT) {
        // Handle the result if needed
    }

    // Call cmsGetTagCount
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        // Handle error
    }

    // Call cmsDetectTAC
    cmsFloat64Number tac = cmsDetectTAC(hProfile);
    if (tac < 0) {
        // Handle error
    }

    // Call cmsGetTagSignature
    cmsTagSignature tagSignature = cmsGetTagSignature(hProfile, tagIndex);
    if (tagSignature == 0) {
        // Handle error
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoLength = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));
    if (infoLength == 0) {
        // Handle error
    }

    // Clean up resources
    cmsCloseProfile(hProfile);

    return 0;
}
