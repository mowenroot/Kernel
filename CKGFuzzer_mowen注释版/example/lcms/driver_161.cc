#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a double from the fuzz input
bool extractDouble(const uint8_t*& data, size_t& size, cmsFloat64Number& value) {
    if (size < sizeof(cmsFloat64Number)) return false;
    memcpy(&value, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);
    return true;
}

// Function to safely extract an integer from the fuzz input
bool extractUInt32(const uint8_t*& data, size_t& size, cmsUInt32Number& value) {
    if (size < sizeof(cmsUInt32Number)) return false;
    memcpy(&value, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);
    return true;
}

// Function to safely extract a cmsCIExyY structure from the fuzz input
bool extractCIExyY(const uint8_t*& data, size_t& size, cmsCIExyY& value) {
    if (size < sizeof(cmsCIExyY)) return false;
    memcpy(&value, data, sizeof(cmsCIExyY));
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = nullptr;
    cmsHPROFILE profileBCHSW = nullptr;
    cmsHPROFILE profileLab4 = nullptr;
    cmsHPROFILE profileLab2 = nullptr;
    cmsCIExyY whitePoint;
    cmsFloat64Number bright, contrast, hue, saturation;
    cmsUInt32Number nLUTPoints, tempSrc, tempDest;

    // Ensure we have enough data to proceed
    if (size < (sizeof(cmsFloat64Number) * 4 + sizeof(cmsUInt32Number) * 3 + sizeof(cmsCIExyY))) {
        return 0;
    }

    // Extract values from fuzz input
    if (!extractDouble(data, size, bright) ||
        !extractDouble(data, size, contrast) ||
        !extractDouble(data, size, hue) ||
        !extractDouble(data, size, saturation) ||
        !extractUInt32(data, size, nLUTPoints) ||
        !extractUInt32(data, size, tempSrc) ||
        !extractUInt32(data, size, tempDest) ||
        !extractCIExyY(data, size, whitePoint)) {
        return 0;
    }

    // Create a context
    context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0;
    }

    // Create BCHSW abstract profile
    profileBCHSW = cmsCreateBCHSWabstractProfileTHR(context, nLUTPoints, bright, contrast, hue, saturation, tempSrc, tempDest);
    if (!profileBCHSW) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create Lab4 profile
    profileLab4 = cmsCreateLab4ProfileTHR(context, &whitePoint);
    if (!profileLab4) {
        cmsCloseProfile(profileBCHSW);
        cmsDeleteContext(context);
        return 0;
    }

    // Create Lab2 profile
    profileLab2 = cmsCreateLab2ProfileTHR(context, &whitePoint);
    if (!profileLab2) {
        cmsCloseProfile(profileBCHSW);
        cmsCloseProfile(profileLab4);
        cmsDeleteContext(context);
        return 0;
    }

    // Clean up
    cmsCloseProfile(profileBCHSW);
    cmsCloseProfile(profileLab4);
    cmsCloseProfile(profileLab2);
    cmsDeleteContext(context);

    return 0;
}
