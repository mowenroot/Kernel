#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input to a buffer
char* SafeStrndup(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = strnlen((const char*)data, size);
    if (len > max_len) len = max_len;
    char* str = (char*)malloc(len + 1);
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Function to safely allocate memory for a string
char* SafeMallocStr(size_t size) {
    char* str = (char*)malloc(size);
    if (str) memset(str, 0, size);
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 10) return 0;

    // Initialize variables
    cmsHANDLE hIT8 = cmsIT8Alloc(nullptr); // Fixed: Added nullptr as argument
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    cmsUInt32Number flags = 0;
    cmsUInt32Number intent = 0;
    cmsUInt32Number dwFlags = 0;
    cmsUInt32Number dwBufferLen = 1024;
    void* buffer = malloc(dwBufferLen);
    wchar_t* infoBuffer = (wchar_t*)malloc(1024 * sizeof(wchar_t));
    char* languageCode = SafeMallocStr(4);
    char* countryCode = SafeMallocStr(4);
    char* patch = SafeStrndup(data, size, 10);
    char* sample = SafeStrndup(data + 10, size - 10, 10);
    char* val = SafeStrndup(data + 20, size - 20, 10);

    // Ensure all allocations succeeded
    if (!hIT8 || !hProfile || !buffer || !infoBuffer || !languageCode || !countryCode || !patch || !sample || !val) {
        goto cleanup;
    }

    // Set data in IT8 table
    if (!cmsIT8SetData(hIT8, patch, sample, val)) {
        goto cleanup;
    }

    // Check if profile is a matrix shaper
    if (cmsIsMatrixShaper(hProfile)) {
        // Handle matrix shaper profile
    }

    // Get PostScript CSA
    cmsUInt32Number bytesUsed;
    if ((bytesUsed = cmsGetPostScriptCSA(NULL, hProfile, intent, dwFlags, buffer, dwBufferLen)) == 0) {
        goto cleanup;
    }

    // Set header flags
    cmsSetHeaderFlags(hProfile, flags);

    // Get profile info
    memcpy(languageCode, "en", 3);
    memcpy(countryCode, "US", 3);
    cmsUInt32Number infoLen;
    if ((infoLen = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, infoBuffer, 1024)) == 0) {
        goto cleanup;
    }

cleanup:
    // Free all allocated resources
    free(buffer);
    free(infoBuffer);
    free(languageCode);
    free(countryCode);
    free(patch);
    free(sample);
    free(val);
    cmsIT8Free(hIT8);
    cmsCloseProfile(hProfile);

    return 0;
}
