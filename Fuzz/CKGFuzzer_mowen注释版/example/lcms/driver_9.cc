#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
const char* SafeStringCopy(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len > size) {
        return nullptr;
    }
    char* str = new char[max_len + 1];
    memcpy(str, data + offset, max_len);
    str[max_len] = '\0';
    offset += max_len;
    return str;
}

// Function to safely get a double value from fuzz input
cmsFloat64Number SafeGetDouble(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsFloat64Number) > size) {
        return 0.0;
    }
    cmsFloat64Number value;
    memcpy(&value, data + offset, sizeof(cmsFloat64Number));
    offset += sizeof(cmsFloat64Number);
    return value;
}

// Function to safely get a uint32 value from fuzz input
cmsUInt32Number SafeGetUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsUInt32Number) > size) {
        return 0;
    }
    cmsUInt32Number value;
    memcpy(&value, data + offset, sizeof(cmsUInt32Number));
    offset += sizeof(cmsUInt32Number);
    return value;
}

// Function to safely get a wchar_t buffer from fuzz input
wchar_t* SafeGetWideBuffer(const uint8_t* data, size_t size, size_t& offset, size_t buffer_size) {
    if (offset + buffer_size * sizeof(wchar_t) > size) {
        return nullptr;
    }
    wchar_t* buffer = new wchar_t[buffer_size];
    memcpy(buffer, data + offset, buffer_size * sizeof(wchar_t));
    offset += buffer_size * sizeof(wchar_t);
    return buffer;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHANDLE it8 = nullptr;
    cmsHPROFILE hProfile = nullptr;
    cmsCIEXYZ blackPoint;
    wchar_t* profileInfoBuffer = nullptr;

    // Ensure we have enough data for basic operations
    if (size < 100) {
        return 0;
    }

    // Create an IT8 handle
    it8 = cmsIT8Alloc(nullptr);
    if (!it8) {
        return 0;
    }

    // Create a profile handle
    hProfile = cmsCreateProfilePlaceholder(nullptr);
    if (!hProfile) {
        cmsIT8Free(it8);
        return 0;
    }

    // Extract and use cmsIT8GetDataDbl
    const char* cPatch = SafeStringCopy(data, size, offset, 10);
    const char* cSample = SafeStringCopy(data, size, offset, 10);
    if (cPatch && cSample) {
        cmsFloat64Number result = cmsIT8GetDataDbl(it8, cPatch, cSample);
        (void)result; // Use the result to avoid unused variable warning
    }
    delete[] cPatch;
    delete[] cSample;

    // Extract and use cmsIsCLUT
    cmsUInt32Number intent = SafeGetUInt32(data, size, offset);
    cmsUInt32Number direction = SafeGetUInt32(data, size, offset);
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, direction);
    (void)isCLUT; // Use the result to avoid unused variable warning

    // Extract and use cmsDetectBlackPoint
    cmsUInt32Number flags = SafeGetUInt32(data, size, offset);
    cmsBool blackPointResult = cmsDetectBlackPoint(&blackPoint, hProfile, intent, flags);
    (void)blackPointResult; // Use the result to avoid unused variable warning

    // Extract and use cmsGetProfileInfo
    const char* languageCode = SafeStringCopy(data, size, offset, 3);
    const char* countryCode = SafeStringCopy(data, size, offset, 3);
    profileInfoBuffer = SafeGetWideBuffer(data, size, offset, 100);
    if (languageCode && countryCode && profileInfoBuffer) {
        cmsUInt32Number infoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, 100);
        (void)infoSize; // Use the result to avoid unused variable warning
    }
    delete[] languageCode;
    delete[] countryCode;
    delete[] profileInfoBuffer;

    // Clean up resources
    cmsCloseProfile(hProfile);
    cmsIT8Free(it8);

    return 0;
}
