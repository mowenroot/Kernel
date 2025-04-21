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
    size_t len = size / sizeof(wchar_t) < max_len ? size / sizeof(wchar_t) : max_len - 1;
    memcpy(dest, src, len * sizeof(wchar_t));
    dest[len] = L'\0';
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) return 0;

    cmsUInt32Number Intent = data[0];
    cmsUInt32Number UsedDirection = data[1];
    cmsUInt64Number Flags = 0;
    cmsUInt32Number BufferSize = 256;
    wchar_t* Buffer = (wchar_t*)malloc(BufferSize * sizeof(wchar_t));
    if (!Buffer) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Extract language and country codes
    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_strncpy(LanguageCode, data + 2, 2, 3);
    safe_strncpy(CountryCode, data + 4, 2, 3);

    // Extract profile info type
    cmsInfoType Info = static_cast<cmsInfoType>(data[6]);

    // Extract PostScript resource type
    cmsPSResourceType Type = static_cast<cmsPSResourceType>(data[7]);

    // Extract PostScript flags
    cmsUInt32Number dwFlags = data[8];

    // Create an IO handler for PostScript resources
    cmsIOHANDLER* io = cmsOpenIOhandlerFromMem(NULL, NULL, 0, "rw");
    if (!io) {
        free(Buffer);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsGetHeaderAttributes
    cmsGetHeaderAttributes(hProfile, &Flags);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsGetPostScriptColorResource
    cmsUInt32Number psResourceResult = cmsGetPostScriptColorResource(NULL, Type, hProfile, Intent, dwFlags, io);

    // Call cmsGetProfileInfo
    cmsUInt32Number profileInfoResult = cmsGetProfileInfo(hProfile, Info, LanguageCode, CountryCode, Buffer, BufferSize);

    // Clean up
    cmsCloseIOhandler(io);
    free(Buffer);
    cmsCloseProfile(hProfile);

    return 0;
}
