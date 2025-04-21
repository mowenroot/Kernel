#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a float from the fuzz input
bool extractFloat(const uint8_t* data, size_t size, size_t& offset, float& value) {
    if (offset + sizeof(float) > size) return false;
    value = *reinterpret_cast<const float*>(data + offset);
    offset += sizeof(float);
    return true;
}

// Function to safely extract a uint32_t from the fuzz input
bool extractUInt32(const uint8_t* data, size_t size, size_t& offset, uint32_t& value) {
    if (offset + sizeof(uint32_t) > size) return false;
    value = *reinterpret_cast<const uint32_t*>(data + offset);
    offset += sizeof(uint32_t);
    return true;
}

// Function to safely extract a cmsCIExyY from the fuzz input
bool extractCIExyY(const uint8_t* data, size_t size, size_t& offset, cmsCIExyY& value) {
    if (offset + sizeof(cmsCIExyY) > size) return false;
    value = *reinterpret_cast<const cmsCIExyY*>(data + offset);
    offset += sizeof(cmsCIExyY);
    return true;
}

// Function to safely extract a cmsCIExyYTRIPLE from the fuzz input
bool extractCIExyYTRIPLE(const uint8_t* data, size_t size, size_t& offset, cmsCIExyYTRIPLE& value) {
    if (offset + sizeof(cmsCIExyYTRIPLE) > size) return false;
    value = *reinterpret_cast<const cmsCIExyYTRIPLE*>(data + offset);
    offset += sizeof(cmsCIExyYTRIPLE);
    return true;
}

// Function to safely extract a cmsToneCurve* from the fuzz input
bool extractToneCurve(const uint8_t* data, size_t size, size_t& offset, cmsToneCurve*& value) {
    if (offset + sizeof(cmsToneCurve*) > size) return false;
    value = *reinterpret_cast<cmsToneCurve**>(const_cast<uint8_t*>(data + offset));
    offset += sizeof(cmsToneCurve*);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) return 0;

    size_t offset = 0;
    float limit;
    uint32_t inputFormat, outputFormat, nIntent, proofingIntent, dwFlags;
    cmsCIExyY whitePoint;
    cmsCIExyYTRIPLE primaries;
    cmsToneCurve* transferFunction[3] = {nullptr, nullptr, nullptr};

    // Extract inputs from fuzz data
    if (!extractFloat(data, size, offset, limit)) return 0;
    if (!extractUInt32(data, size, offset, inputFormat)) return 0;
    if (!extractUInt32(data, size, offset, outputFormat)) return 0;
    if (!extractUInt32(data, size, offset, nIntent)) return 0;
    if (!extractUInt32(data, size, offset, proofingIntent)) return 0;
    if (!extractUInt32(data, size, offset, dwFlags)) return 0;
    if (!extractCIExyY(data, size, offset, whitePoint)) return 0;
    if (!extractCIExyYTRIPLE(data, size, offset, primaries)) return 0;
    if (!extractToneCurve(data, size, offset, transferFunction[0])) return 0;
    if (!extractToneCurve(data, size, offset, transferFunction[1])) return 0;
    if (!extractToneCurve(data, size, offset, transferFunction[2])) return 0;

    // Create profiles
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
