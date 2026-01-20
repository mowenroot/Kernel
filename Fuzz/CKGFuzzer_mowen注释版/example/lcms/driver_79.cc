#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a uint32_t from the fuzzer input
uint32_t ExtractUInt32(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value = *reinterpret_cast<const uint32_t*>(data + offset);
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a double from the fuzzer input
double ExtractDouble(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Return a default value if not enough data
    }
    double value = *reinterpret_cast<const double*>(data + offset);
    offset += sizeof(double);
    return value;
}

// Function to safely extract a cmsCIExyY from the fuzzer input
cmsCIExyY ExtractCIExyY(const uint8_t* data, size_t& offset, size_t size) {
    cmsCIExyY xyY;
    if (offset + sizeof(cmsCIExyY) > size) {
        xyY.x = 0.0;
        xyY.y = 0.0;
        xyY.Y = 0.0;
        return xyY; // Return a default value if not enough data
    }
    xyY = *reinterpret_cast<const cmsCIExyY*>(data + offset);
    offset += sizeof(cmsCIExyY);
    return xyY;
}

// Function to safely extract a cmsToneCurve* array from the fuzzer input
std::unique_ptr<cmsToneCurve*[]> ExtractToneCurves(const uint8_t* data, size_t& offset, size_t size, cmsUInt32Number nChannels) {
    auto toneCurves = std::make_unique<cmsToneCurve*[]>(nChannels);
    for (cmsUInt32Number i = 0; i < nChannels; ++i) {
        if (offset + sizeof(cmsToneCurve*) > size) {
            toneCurves[i] = nullptr;
        } else {
            // Use const_cast to avoid casting away qualifiers
            toneCurves[i] = const_cast<cmsToneCurve*>(*reinterpret_cast<const cmsToneCurve* const*>(data + offset));
            offset += sizeof(cmsToneCurve*);
        }
    }
    return toneCurves;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) return 0;

    size_t offset = 0;

    // Extract parameters from fuzzer input
    uint32_t colorSpace = ExtractUInt32(data, offset, size);
    double inkLimit = ExtractDouble(data, offset, size);
    cmsCIExyY whitePoint = ExtractCIExyY(data, offset, size);
    uint32_t inputFormat = ExtractUInt32(data, offset, size);
    uint32_t outputFormat = ExtractUInt32(data, offset, size);
    uint32_t intent = ExtractUInt32(data, offset, size);
    uint32_t proofingIntent = ExtractUInt32(data, offset, size);
    uint32_t flags = ExtractUInt32(data, offset, size);
    cmsUInt32Number nProfiles = ExtractUInt32(data, offset, size);

    // Create profiles and transforms
    cmsHPROFILE inkLimitingProfile = cmsCreateInkLimitingDeviceLinkTHR(context, static_cast<cmsColorSpaceSignature>(colorSpace), inkLimit);
    if (!inkLimitingProfile) {
        cmsDeleteContext(context);
        return 0;
    }

    cmsHPROFILE labProfile = cmsCreateLab2ProfileTHR(context, &whitePoint);
    if (!labProfile) {
        cmsCloseProfile(inkLimitingProfile);
        cmsDeleteContext(context);
        return 0;
    }

    cmsHPROFILE proofingProfile = cmsCreateLab2ProfileTHR(context, &whitePoint);
    if (!proofingProfile) {
        cmsCloseProfile(labProfile);
        cmsCloseProfile(inkLimitingProfile);
        cmsDeleteContext(context);
        return 0;
    }

    cmsHTRANSFORM proofingTransform = cmsCreateProofingTransformTHR(context, inkLimitingProfile, inputFormat, labProfile, outputFormat, proofingProfile, intent, proofingIntent, flags);
    if (!proofingTransform) {
        cmsCloseProfile(proofingProfile);
        cmsCloseProfile(labProfile);
        cmsCloseProfile(inkLimitingProfile);
        cmsDeleteContext(context);
        return 0;
    }

    cmsHTRANSFORM multiProfileTransform = cmsCreateMultiprofileTransformTHR(context, &inkLimitingProfile, nProfiles, inputFormat, outputFormat, intent, flags);
    if (!multiProfileTransform) {
        cmsDeleteTransform(proofingTransform);
        cmsCloseProfile(proofingProfile);
        cmsCloseProfile(labProfile);
        cmsCloseProfile(inkLimitingProfile);
        cmsDeleteContext(context);
        return 0;
    }

    // Cleanup
    cmsDeleteTransform(proofingTransform);
    cmsDeleteTransform(multiProfileTransform);
    cmsCloseProfile(proofingProfile);
    cmsCloseProfile(labProfile);
    cmsCloseProfile(inkLimitingProfile);
    cmsDeleteContext(context);

    return 0;
}
