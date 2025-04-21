#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a double from the fuzz input
bool extractDouble(const uint8_t* data, size_t size, size_t& offset, cmsFloat64Number& value) {
    if (offset + sizeof(cmsFloat64Number) > size) return false;
    memcpy(&value, data + offset, sizeof(cmsFloat64Number));
    offset += sizeof(cmsFloat64Number);
    return true;
}

// Function to safely extract a cmsCIExyY structure from the fuzz input
bool extractCIExyY(const uint8_t* data, size_t size, size_t& offset, cmsCIExyY& whitePoint) {
    if (offset + sizeof(cmsCIExyY) > size) return false;
    memcpy(&whitePoint, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return true;
}

// Function to safely extract a cmsTagSignature from the fuzz input
bool extractTagSignature(const uint8_t* data, size_t size, size_t& offset, cmsTagSignature& tagSig) {
    if (offset + sizeof(cmsTagSignature) > size) return false;
    memcpy(&tagSig, data + offset, sizeof(cmsTagSignature));
    offset += sizeof(cmsTagSignature);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsFloat64Number tempK = 0.0;
    cmsCIExyY whitePoint;
    cmsTagSignature tagSig = (cmsTagSignature)0;
    cmsHPROFILE hProfile = nullptr;
    cmsHTRANSFORM hTransform = nullptr;
    cmsTagSignature linkedTag = (cmsTagSignature)0;

    // Extract data from fuzz input
    if (!extractDouble(data, size, offset, tempK)) return 0;
    if (!extractCIExyY(data, size, offset, whitePoint)) return 0;
    if (!extractTagSignature(data, size, offset, tagSig)) return 0;

    // Calculate white point from temperature
    if (!cmsWhitePointFromTemp(&whitePoint, tempK)) {
        return 0; // Handle error
    }

    // Calculate temperature from white point
    if (!cmsTempFromWhitePoint(&tempK, &whitePoint)) {
        return 0; // Handle error
    }

    // Create a dummy profile for testing
    hProfile = cmsCreateProfilePlaceholder(nullptr);
    if (!hProfile) return 0; // Handle error

    // Find linked tag
    linkedTag = cmsTagLinkedTo(hProfile, tagSig);

    // Create a device link profile
    hTransform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (!hTransform) {
        cmsCloseProfile(hProfile);
        return 0; // Handle error
    }

    cmsHPROFILE deviceLinkProfile = cmsTransform2DeviceLink(hTransform, 4.0, 0);
    if (!deviceLinkProfile) {
        cmsDeleteTransform(hTransform);
        cmsCloseProfile(hProfile);
        return 0; // Handle error
    }

    // Clean up
    cmsDeleteTransform(hTransform);
    cmsCloseProfile(hProfile);
    cmsCloseProfile(deviceLinkProfile);

    return 0;
}
