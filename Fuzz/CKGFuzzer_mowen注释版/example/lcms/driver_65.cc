#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len - 1;
    memcpy(dest, src, len);
    dest[len] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len - 1;
    for (size_t i = 0; i < len; ++i) {
        dest[i] = static_cast<wchar_t>(src[i]);
    }
    dest[len] = L'\0';
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    // Extract parameters from fuzz input
    cmsUInt32Number Intent = static_cast<cmsUInt32Number>(data[0]);
    cmsUInt32Number UsedDirection = static_cast<cmsUInt32Number>(data[1]);
    cmsColorSpaceSignature pcs = static_cast<cmsColorSpaceSignature>(data[2]);
    cmsUInt32Number Flags = static_cast<cmsUInt32Number>(data[3]);

    // Extract language and country codes
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_strncpy(LanguageCode, data + 4, 2, 3);
    safe_strncpy(CountryCode, data + 6, 2, 3);

    // Extract buffer size for profile info
    cmsUInt32Number BufferSize = static_cast<cmsUInt32Number>(data[8]) + 1; // Ensure at least 1 byte for null terminator
    wchar_t* Buffer = (wchar_t*)malloc(BufferSize * sizeof(wchar_t));
    if (!Buffer) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Initialize buffer to avoid undefined behavior
    memset(Buffer, 0, BufferSize * sizeof(wchar_t));

    // Call APIs with extracted parameters
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);
    cmsSetPCS(hProfile, pcs);
    cmsBool isCLUT = cmsIsCLUT(hProfile, Intent, UsedDirection);
    cmsSetHeaderFlags(hProfile, Flags);
    cmsUInt32Number infoLength = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, BufferSize);

    // Handle potential errors
    if (isIntentSupported == FALSE || isCLUT == FALSE || infoLength == 0) {
        free(Buffer);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Clean up
    free(Buffer);
    cmsCloseProfile(hProfile);

    return 0;
}
