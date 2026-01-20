#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
const char* SafeStringCopy(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len > size) return nullptr;
    char* str = (char*)malloc(max_len + 1);
    if (!str) return nullptr;
    memcpy(str, data + offset, max_len);
    str[max_len] = '\0';
    offset += max_len;
    return str;
}

// Function to safely copy a wide string from fuzz input
const wchar_t* SafeWideStringCopy(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len * sizeof(wchar_t) > size) return nullptr;
    wchar_t* wstr = (wchar_t*)malloc((max_len + 1) * sizeof(wchar_t));
    if (!wstr) return nullptr;
    memcpy(wstr, data + offset, max_len * sizeof(wchar_t));
    wstr[max_len] = L'\0';
    offset += max_len * sizeof(wchar_t);
    return wstr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = nullptr;
    cmsHPROFILE profile = nullptr;
    cmsHANDLE it8 = nullptr;
    const char* languageCode = nullptr;
    const char* countryCode = nullptr;
    const wchar_t* buffer = nullptr;
    size_t offset = 0;

    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Create a new context
    context = cmsCreateContext(nullptr, nullptr);
    if (!context) return 0;

    // Duplicate the context
    cmsContext dupContext = cmsDupContext(context, nullptr);
    if (!dupContext) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a Lab4 profile
    profile = cmsCreateLab4ProfileTHR(dupContext, nullptr);
    if (!profile) {
        cmsDeleteContext(dupContext);
        cmsDeleteContext(context);
        return 0;
    }

    // Allocate an IT8 structure
    it8 = cmsIT8Alloc(dupContext);
    if (!it8) {
        cmsCloseProfile(profile);
        cmsDeleteContext(dupContext);
        cmsDeleteContext(context);
        return 0;
    }

    // Get profile information
    languageCode = SafeStringCopy(data, size, offset, 3);
    countryCode = SafeStringCopy(data, size, offset, 3);
    buffer = SafeWideStringCopy(data, size, offset, 256);
    if (languageCode && countryCode && buffer) {
        cmsGetProfileInfo(profile, cmsInfoDescription, languageCode, countryCode, (wchar_t*)buffer, 256);
    }

    // Write a tag to the profile
    cmsTagSignature tagSig = (cmsTagSignature)(data[offset] % 256);
    offset++;
    if (offset + sizeof(cmsUInt32Number) <= size) {
        cmsUInt32Number tagData = *(cmsUInt32Number*)(data + offset);
        offset += sizeof(cmsUInt32Number);
        cmsWriteTag(profile, tagSig, &tagData);
    }

    // Clean up
    free((void*)languageCode);
    free((void*)countryCode);
    free((void*)buffer);
    cmsIT8Free(it8);
    cmsCloseProfile(profile);
    cmsDeleteContext(dupContext);
    cmsDeleteContext(context);

    return 0;
}
