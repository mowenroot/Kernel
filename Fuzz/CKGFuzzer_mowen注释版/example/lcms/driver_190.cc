#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint32_t from the fuzz input
uint32_t extractUint32(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a cmsCIExyY from the fuzz input
cmsCIExyY extractCIExyY(const uint8_t* data, size_t& offset, size_t size) {
    cmsCIExyY xyY;
    if (offset + sizeof(cmsCIExyY) > size) {
        xyY.x = 0.0;
        xyY.y = 0.0;
        xyY.Y = 0.0;
        return xyY; // Return a default value if not enough data
    }
    memcpy(&xyY, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return xyY;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) return 0;

    size_t offset = 0;

    // Extract parameters from fuzz input
    cmsCIExyY whitePoint = extractCIExyY(data, offset, size);
    uint32_t inputFormat = extractUint32(data, offset, size);
    uint32_t outputFormat = extractUint32(data, offset, size);
    uint32_t nIntent = extractUint32(data, offset, size);
    uint32_t proofingIntent = extractUint32(data, offset, size);
    uint32_t dwFlags = extractUint32(data, offset, size);

    // Create profiles
    cmsHPROFILE lab4Profile = cmsCreateLab4ProfileTHR(context, &whitePoint);
    cmsHPROFILE lab2Profile = cmsCreateLab2ProfileTHR(context, &whitePoint);

    if (!lab4Profile || !lab2Profile) {
        if (lab4Profile) cmsCloseProfile(lab4Profile);
        if (lab2Profile) cmsCloseProfile(lab2Profile);
        cmsDeleteContext(context);
        return 0;
    }

    // Create transforms
    cmsHTRANSFORM transform1 = cmsCreateTransformTHR(context, lab4Profile, inputFormat, lab2Profile, outputFormat, nIntent, dwFlags);
    cmsHTRANSFORM transform2 = cmsCreateProofingTransformTHR(context, lab4Profile, inputFormat, lab2Profile, outputFormat, lab2Profile, nIntent, proofingIntent, dwFlags);

    if (!transform1 || !transform2) {
        if (transform1) cmsDeleteTransform(transform1);
        if (transform2) cmsDeleteTransform(transform2);
        cmsCloseProfile(lab4Profile);
        cmsCloseProfile(lab2Profile);
        cmsDeleteContext(context);
        return 0;
    }

    // Clean up
    cmsDeleteTransform(transform1);
    cmsDeleteTransform(transform2);
    cmsCloseProfile(lab4Profile);
    cmsCloseProfile(lab2Profile);
    cmsDeleteContext(context);

    return 0;
}
