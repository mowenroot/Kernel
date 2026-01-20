#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
void safe_strncpy(char* dest, const uint8_t* src, size_t size, size_t max_size) {
    size_t copy_size = size < max_size ? size : max_size - 1;
    memcpy(dest, src, copy_size);
    dest[copy_size] = '\0';
}

// Function to safely copy a wide string from fuzz input
void safe_wcsncpy(wchar_t* dest, const uint8_t* src, size_t size, size_t max_size) {
    size_t copy_size = size < max_size ? size : max_size - 1;
    for (size_t i = 0; i < copy_size; ++i) {
        dest[i] = static_cast<wchar_t>(src[i]);
    }
    dest[copy_size] = L'\0';
}

// Main fuzzing function
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

    char LanguageCode[3] = {0};
    char CountryCode[3] = {0};
    safe_strncpy(LanguageCode, data + 2, 2, 3);
    safe_strncpy(CountryCode, data + 4, 2, 3);

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, Intent, UsedDirection);

    // Call cmsGetHeaderAttributes
    cmsGetHeaderAttributes(hProfile, &Flags);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsGetPostScriptColorResource
    cmsIOHANDLER* io = cmsOpenIOhandlerFromNULL(NULL); // Pass NULL as ContextID
    if (io) {
        cmsUInt32Number psResource = cmsGetPostScriptColorResource(NULL, cmsPS_RESOURCE_CSA, hProfile, Intent, 0, io);
        cmsCloseIOhandler(io);
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, LanguageCode, CountryCode, Buffer, BufferSize);

    // Clean up
    free(Buffer);
    cmsCloseProfile(hProfile);

    return 0;
}
