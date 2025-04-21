#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint32_t from the fuzz input
uint32_t SafeExtractUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value = *reinterpret_cast<const uint32_t*>(data + offset);
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a cmsCIExyY from the fuzz input
cmsCIExyY SafeExtractCIExyY(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyY xyY;
    if (offset + sizeof(cmsCIExyY) > size) {
        memset(&xyY, 0, sizeof(cmsCIExyY)); // Initialize to zero if not enough data
    } else {
        memcpy(&xyY, data + offset, sizeof(cmsCIExyY));
        offset += sizeof(cmsCIExyY);
    }
    return xyY;
}

// Function to safely extract a cmsCIExyYTRIPLE from the fuzz input
cmsCIExyYTRIPLE SafeExtractCIExyYTRIPLE(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyYTRIPLE xyYTriple;
    if (offset + sizeof(cmsCIExyYTRIPLE) > size) {
        memset(&xyYTriple, 0, sizeof(cmsCIExyYTRIPLE)); // Initialize to zero if not enough data
    } else {
        memcpy(&xyYTriple, data + offset, sizeof(cmsCIExyYTRIPLE));
        offset += sizeof(cmsCIExyYTRIPLE);
    }
    return xyYTriple;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) return 0;

    size_t offset = 0;

    // Extract inputs from fuzz data
    cmsCIExyY whitePoint = SafeExtractCIExyY(data, size, offset);
    cmsCIExyYTRIPLE primaries = SafeExtractCIExyYTRIPLE(data, size, offset);
    uint32_t intent = SafeExtractUInt32(data, size, offset);
    uint32_t proofingIntent = SafeExtractUInt32(data, size, offset);
    uint32_t flags = SafeExtractUInt32(data, size, offset);

    // Create profiles
    cmsHPROFILE lab4Profile = cmsCreateLab4ProfileTHR(context, &whitePoint);
    cmsHPROFILE rgbProfile = cmsCreateRGBProfileTHR(context, &whitePoint, &primaries, NULL);
    cmsHPROFILE lab2Profile = cmsCreateLab2ProfileTHR(context, &whitePoint);
    cmsHPROFILE xyzProfile = cmsCreateXYZProfileTHR(context);
    cmsHPROFILE sRGBProfile = cmsCreate_sRGBProfileTHR(context);

    // Create proofing transform
    cmsHTRANSFORM transform = cmsCreateProofingTransformTHR(context, lab4Profile, 0, rgbProfile, 0, sRGBProfile, intent, proofingIntent, flags);

    // Clean up
    if (lab4Profile) cmsCloseProfile(lab4Profile);
    if (rgbProfile) cmsCloseProfile(rgbProfile);
    if (lab2Profile) cmsCloseProfile(lab2Profile);
    if (xyzProfile) cmsCloseProfile(xyzProfile);
    if (sRGBProfile) cmsCloseProfile(sRGBProfile);
    if (transform) cmsDeleteTransform(transform);

    cmsDeleteContext(context);

    return 0;
}
