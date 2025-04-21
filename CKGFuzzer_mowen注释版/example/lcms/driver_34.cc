#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert a byte array to a 32-bit unsigned integer
cmsUInt32Number getUInt32FromData(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsUInt32Number) > size) {
        return 0; // Out of bounds
    }
    cmsUInt32Number value = *reinterpret_cast<const cmsUInt32Number*>(data + offset);
    offset += sizeof(cmsUInt32Number);
    return value;
}

// Function to convert a byte array to a double
double getDoubleFromData(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Out of bounds
    }
    double value = *reinterpret_cast<const double*>(data + offset);
    offset += sizeof(double);
    return value;
}

// Function to convert a byte array to a cmsCIELab structure
void getLabFromData(const uint8_t* data, size_t& offset, cmsCIELab& lab, size_t size) {
    lab.L = getDoubleFromData(data, offset, size);
    lab.a = getDoubleFromData(data, offset, size);
    lab.b = getDoubleFromData(data, offset, size);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const size_t MAX_INPUT_SIZE = 1024; // Limit input size to prevent excessive memory usage
    if (size > MAX_INPUT_SIZE) {
        return 0; // Input too large
    }

    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = nullptr;
    cmsCIELab lab = {0.0, 0.0, 0.0};
    cmsCIELCh lch = {0.0, 0.0, 0.0};
    double amax, amin, bmax, bmin;
    cmsUInt32Number intent, usedDirection;

    // Extract data from fuzzer input
    hProfile = cmsOpenProfileFromMem(data, size);
    if (!hProfile) {
        return 0; // Failed to open profile
    }

    intent = getUInt32FromData(data, offset, size);
    usedDirection = getUInt32FromData(data, offset, size);
    getLabFromData(data, offset, lab, size);
    amax = getDoubleFromData(data, offset, size);
    amin = getDoubleFromData(data, offset, size);
    bmax = getDoubleFromData(data, offset, size);
    bmin = getDoubleFromData(data, offset, size);

    // Call APIs with extracted data
    cmsIsIntentSupported(hProfile, intent, usedDirection);
    cmsIsCLUT(hProfile, intent, usedDirection);
    cmsDesaturateLab(&lab, amax, amin, bmax, bmin);
    cmsDetectTAC(hProfile);
    cmsLab2LCh(&lch, &lab);

    // Clean up
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
