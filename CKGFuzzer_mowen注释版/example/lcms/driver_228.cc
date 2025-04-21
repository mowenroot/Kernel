#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a cmsUInt32Number
cmsUInt32Number safe_convert_to_cmsUInt32Number(const uint8_t* data, size_t size, size_t index) {
    if (index >= size) return 0; // Default value if out of bounds
    return static_cast<cmsUInt32Number>(data[index]);
}

// Function to safely convert fuzz input to a string
void safe_convert_to_string(const uint8_t* data, size_t size, size_t index, char* buffer, size_t buffer_size) {
    if (index + buffer_size > size) {
        buffer[0] = '\0'; // Default to empty string if out of bounds
    } else {
        memcpy(buffer, data + index, buffer_size);
        buffer[buffer_size - 1] = '\0'; // Ensure null-termination
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0; // Handle profile creation failure

    cmsUInt32Number Intent = safe_convert_to_cmsUInt32Number(data, size, 0);
    cmsUInt32Number UsedDirection = safe_convert_to_cmsUInt32Number(data, size, 4);
    cmsUInt32Number nMax = safe_convert_to_cmsUInt32Number(data, size, 8);
    cmsUInt32Number BufferSize = safe_convert_to_cmsUInt32Number(data, size, 12);

    // Allocate memory for intent codes and descriptions
    cmsUInt32Number* Codes = (cmsUInt32Number*)malloc(nMax * sizeof(cmsUInt32Number));
    char** Descriptions = (char**)malloc(nMax * sizeof(char*));
    for (cmsUInt32Number i = 0; i < nMax; ++i) {
        Descriptions[i] = (char*)malloc(256); // Assuming max description length of 255 characters
    }

    // Allocate memory for profile info buffer
    wchar_t* Buffer = (wchar_t*)malloc(BufferSize * sizeof(wchar_t));

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsGetTagCount
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);

    // Call cmsGetSupportedIntents
    cmsUInt32Number supportedIntentsCount = cmsGetSupportedIntents(nMax, Codes, Descriptions);

    // Prepare language and country codes
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_convert_to_string(data, size, 16, LanguageCode, 3);
    safe_convert_to_string(data, size, 19, CountryCode, 3);

    // Call cmsGetProfileInfo
    cmsUInt32Number profileInfoLength = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, BufferSize);

    // Free allocated resources
    for (cmsUInt32Number i = 0; i < nMax; ++i) {
        free(Descriptions[i]);
    }
    free(Descriptions);
    free(Codes);
    free(Buffer);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}
