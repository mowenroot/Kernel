#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
const char* SafeStringCopy(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len > size) return nullptr;
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += max_len;
    return str;
}

// Function to safely copy a wide string from fuzz input
const wchar_t* SafeWideStringCopy(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len * sizeof(wchar_t) > size) return nullptr;
    const wchar_t* str = reinterpret_cast<const wchar_t*>(data + offset);
    offset += max_len * sizeof(wchar_t);
    return str;
}

// Function to safely copy a CIExyY structure from fuzz input
cmsCIExyY SafeCIExyYCopy(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyY xyY;
    if (offset + sizeof(cmsCIExyY) > size) {
        memset(&xyY, 0, sizeof(cmsCIExyY));
        return xyY;
    }
    memcpy(&xyY, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return xyY;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = nullptr;
    cmsHANDLE hIT8 = nullptr;
    cmsBool result = FALSE;
    cmsCIExyY whitePoint;
    const char* languageCode = nullptr;
    const char* countryCode = nullptr;
    const char* patch = nullptr;
    const char* sample = nullptr;
    const char* value = nullptr;
    wchar_t buffer[256];

    // Ensure we have enough data for basic operations
    if (size < sizeof(cmsCIExyY) + 6 * sizeof(char) + 3 * sizeof(wchar_t)) return 0;

    // Copy and initialize data from fuzz input
    whitePoint = SafeCIExyYCopy(data, size, offset);
    languageCode = SafeStringCopy(data, size, offset, 3);
    countryCode = SafeStringCopy(data, size, offset, 3);
    patch = SafeStringCopy(data, size, offset, 32);
    sample = SafeStringCopy(data, size, offset, 32);
    value = SafeStringCopy(data, size, offset, 32);

    // Create a Lab 4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) return 0;

    // Check if intent is supported
    result = cmsIsIntentSupported(hProfile, 0, 0);
    if (!result) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Get profile info
    cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, buffer, sizeof(buffer));

    // Create an IT8 handle
    hIT8 = cmsIT8Alloc(nullptr);
    if (!hIT8) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Set data in IT8 table
    result = cmsIT8SetData(hIT8, patch, sample, value);
    if (!result) {
        cmsIT8Free(hIT8);
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Free resources
    cmsIT8Free(hIT8);
    cmsCloseProfile(hProfile);

    return 0;
}
