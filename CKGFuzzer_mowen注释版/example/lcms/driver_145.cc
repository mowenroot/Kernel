#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzz input to a cmsUInt32Number
cmsUInt32Number safe_convert_to_cmsUInt32Number(const uint8_t* data, size_t size, size_t index) {
    if (index >= size) return 0;
    return static_cast<cmsUInt32Number>(data[index]);
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

// Function to safely convert fuzz input to a wchar_t buffer
void safe_convert_to_wchar_buffer(const uint8_t* data, size_t size, size_t index, wchar_t* buffer, size_t buffer_size) {
    if (index + buffer_size > size) {
        buffer[0] = L'\0';
        return;
    }
    for (size_t i = 0; i < buffer_size; ++i) {
        buffer[i] = static_cast<wchar_t>(data[index + i]);
    }
    buffer[buffer_size - 1] = L'\0';
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < 16) return 0;

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // RAII wrapper for the profile handle
    std::unique_ptr<void, void(*)(void*)> profile_guard(hProfile, [](void* p) { cmsCloseProfile(p); });

    // Extract parameters from fuzz input
    cmsUInt32Number Intent = safe_convert_to_cmsUInt32Number(data, size, 0);
    cmsUInt32Number UsedDirection = safe_convert_to_cmsUInt32Number(data, size, 4);
    cmsInfoType Info = static_cast<cmsInfoType>(safe_convert_to_cmsUInt32Number(data, size, 8));

    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_convert_to_string(data, size, 12, LanguageCode, 2);
    safe_convert_to_string(data, size, 14, CountryCode, 2);

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsMD5computeID
    cmsBool md5Computed = cmsMD5computeID(hProfile);

    // Call cmsGetProfileInfo
    wchar_t buffer[256] = {0};
    cmsUInt32Number infoLength = cmsGetProfileInfo(hProfile, Info, LanguageCode, CountryCode, buffer, sizeof(buffer) / sizeof(buffer[0]));

    // Ensure all resources are freed and no memory leaks occur
    return 0;
}
