#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a float from the fuzz input
bool safe_extract_float(const uint8_t* data, size_t size, size_t& offset, float& value) {
    if (offset + sizeof(float) > size) return false;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return true;
}

// Function to safely extract a uint32_t from the fuzz input
bool safe_extract_uint32(const uint8_t* data, size_t size, size_t& offset, uint32_t& value) {
    if (offset + sizeof(uint32_t) > size) return false;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return true;
}

// Function to safely extract a cmsCIExyY from the fuzz input
bool safe_extract_cmsCIExyY(const uint8_t* data, size_t size, size_t& offset, cmsCIExyY& value) {
    if (offset + sizeof(cmsCIExyY) > size) return false;
    memcpy(&value, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return true;
}

// Function to safely extract a cmsCIExyYTRIPLE from the fuzz input
bool safe_extract_cmsCIExyYTRIPLE(const uint8_t* data, size_t size, size_t& offset, cmsCIExyYTRIPLE& value) {
    if (offset + sizeof(cmsCIExyYTRIPLE) > size) return false;
    memcpy(&value, data + offset, sizeof(cmsCIExyYTRIPLE));
    offset += sizeof(cmsCIExyYTRIPLE);
    return true;
}

// Function to safely extract a cmsToneCurve* from the fuzz input
bool safe_extract_cmsToneCurve(const uint8_t* data, size_t size, size_t& offset, cmsToneCurve*& value) {
    if (offset + sizeof(cmsToneCurve*) > size) return false;
    memcpy(&value, data + offset, sizeof(cmsToneCurve*));
    offset += sizeof(cmsToneCurve*);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) return 0;

    size_t offset = 0;
    float limit;
    uint32_t inputFormat, outputFormat, nIntent, proofingIntent, dwFlags;
    cmsCIExyY whitePoint;
    cmsCIExyYTRIPLE primaries;
    cmsToneCurve* transferFunction[3];

    // Extract inputs from fuzz data
    if (!safe_extract_float(data, size, offset, limit)) return 0;
    if (!safe_extract_uint32(data, size, offset, inputFormat)) return 0;
    if (!safe_extract_uint32(data, size, offset, outputFormat)) return 0;
    if (!safe_extract_uint32(data, size, offset, nIntent)) return 0;
    if (!safe_extract_uint32(data, size, offset, proofingIntent)) return 0;
    if (!safe_extract_uint32(data, size, offset, dwFlags)) return 0;
    if (!safe_extract_cmsCIExyY(data, size, offset, whitePoint)) return 0;
    if (!safe_extract_cmsCIExyYTRIPLE(data, size, offset, primaries)) return 0;
    if (!safe_extract_cmsToneCurve(data, size, offset, transferFunction[0])) return 0;
    if (!safe_extract_cmsToneCurve(data, size, offset, transferFunction[1])) return 0;
    if (!safe_extract_cmsToneCurve(data, size, offset, transferFunction[2])) return 0;

    // Create profiles and transforms
    cmsHPROFILE inkLimitingProfile = cmsCreateInkLimitingDeviceLinkTHR(context, cmsSigCmykData, limit);
    cmsHPROFILE rgbProfile = cmsCreateRGBProfileTHR(context, &whitePoint, &primaries, transferFunction);
    cmsHPROFILE labProfile = cmsCreateLab2ProfileTHR(context, &whitePoint);
    cmsHPROFILE xyzProfile = cmsCreateXYZProfileTHR(context);
    cmsHPROFILE sRGBProfile = cmsCreate_sRGBProfileTHR(context);

    // Create proofing transform
    cmsHTRANSFORM proofingTransform = cmsCreateProofingTransformTHR(context, inkLimitingProfile, inputFormat, rgbProfile, outputFormat, labProfile, nIntent, proofingIntent, dwFlags);

    // Clean up
    if (inkLimitingProfile) cmsCloseProfile(inkLimitingProfile);
    if (rgbProfile) cmsCloseProfile(rgbProfile);
    if (labProfile) cmsCloseProfile(labProfile);
    if (xyzProfile) cmsCloseProfile(xyzProfile);
    if (sRGBProfile) cmsCloseProfile(sRGBProfile);
    if (proofingTransform) cmsDeleteTransform(proofingTransform);

    cmsDeleteContext(context);
    return 0;
}
