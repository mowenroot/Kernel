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
    char* str = (char*)malloc(max_len + 1);
    if (!str) {
        return nullptr;
    }
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
    cmsFloat64Number val;
    memcpy(&val, data + offset, sizeof(cmsFloat64Number));
    offset += sizeof(cmsFloat64Number);
    return val;
}

// Function to safely get an integer value from fuzz input
cmsUInt32Number SafeGetUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsUInt32Number) > size) {
        return 0;
    }
    cmsUInt32Number val;
    memcpy(&val, data + offset, sizeof(cmsUInt32Number));
    offset += sizeof(cmsUInt32Number);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    if (!hIT8) {
        return 0;
    }

    // Safely get property name and value
    const char* propName = SafeStringCopy(data, size, offset, 32);
    if (!propName) {
        cmsIT8Free(hIT8);
        return 0;
    }
    cmsFloat64Number propValue = SafeGetDouble(data, size, offset);

    // Call cmsIT8SetPropertyDbl
    cmsBool setPropResult = cmsIT8SetPropertyDbl(hIT8, propName, propValue);
    if (!setPropResult) {
        free((void*)propName);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Call cmsIT8GetProperty
    const char* getPropResult = cmsIT8GetProperty(hIT8, propName);
    if (getPropResult) {
        // Handle the result if needed
    }

    // Create a tone curve
    cmsToneCurve* toneCurve = cmsBuildTabulatedToneCurve16(NULL, 256, nullptr);
    if (!toneCurve) {
        free((void*)propName);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Safely get lambda value
    cmsFloat64Number lambda = SafeGetDouble(data, size, offset);

    // Call cmsSmoothToneCurve
    cmsBool smoothResult = cmsSmoothToneCurve(toneCurve, lambda);
    if (!smoothResult) {
        cmsFreeToneCurve(toneCurve);
        free((void*)propName);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Call cmsIsToneCurveMonotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);
    if (!isMonotonic) {
        // Handle the result if needed
    }

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (!hProfile) {
        cmsFreeToneCurve(toneCurve);
        free((void*)propName);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Safely get intent and flags
    cmsUInt32Number intent = SafeGetUInt32(data, size, offset);
    cmsUInt32Number flags = SafeGetUInt32(data, size, offset);

    // Call cmsDetectBlackPoint
    cmsCIEXYZ blackPoint;
    cmsBool detectResult = cmsDetectBlackPoint(&blackPoint, hProfile, intent, flags);
    if (!detectResult) {
        // Handle the result if needed
    }

    // Clean up
    cmsCloseProfile(hProfile);
    cmsFreeToneCurve(toneCurve);
    free((void*)propName);
    cmsIT8Free(hIT8);

    return 0;
}
