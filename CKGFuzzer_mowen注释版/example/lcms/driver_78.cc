#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a double from the fuzz input
double extractDouble(const uint8_t*& data, size_t& size) {
    if (size < sizeof(double)) {
        return 0.0; // Return a default value if not enough data
    }
    double value;
    memcpy(&value, data, sizeof(double));
    data += sizeof(double);
    size -= sizeof(double);
    return value;
}

// Function to safely extract a cmsCIExyY structure from the fuzz input
cmsCIExyY extractCIExyY(const uint8_t*& data, size_t& size) {
    cmsCIExyY xyY;
    if (size < sizeof(cmsCIExyY)) {
        memset(&xyY, 0, sizeof(cmsCIExyY)); // Initialize to zero if not enough data
        return xyY;
    }
    memcpy(&xyY, data, sizeof(cmsCIExyY));
    data += sizeof(cmsCIExyY);
    size -= sizeof(cmsCIExyY);
    return xyY;
}

// Function to safely extract a cmsCIELab structure from the fuzz input
cmsCIELab extractCIELab(const uint8_t*& data, size_t& size) {
    cmsCIELab Lab;
    if (size < sizeof(cmsCIELab)) {
        memset(&Lab, 0, sizeof(cmsCIELab)); // Initialize to zero if not enough data
        return Lab;
    }
    memcpy(&Lab, data, sizeof(cmsCIELab));
    data += sizeof(cmsCIELab);
    size -= sizeof(cmsCIELab);
    return Lab;
}

// Function to safely extract a cmsToneCurve* array from the fuzz input
cmsToneCurve** extractToneCurves(const uint8_t*& data, size_t& size, int nChannels) {
    cmsToneCurve** curves = (cmsToneCurve**)malloc(nChannels * sizeof(cmsToneCurve*));
    if (!curves) return nullptr;

    for (int i = 0; i < nChannels; ++i) {
        if (size < sizeof(cmsToneCurve*)) {
            for (int j = 0; j < i; ++j) free(curves[j]); // Use free instead of cmsFree
            free(curves); // Use free instead of cmsFree
            return nullptr;
        }
        curves[i] = (cmsToneCurve*)data;
        data += sizeof(cmsToneCurve*);
        size -= sizeof(cmsToneCurve*);
    }
    return curves;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) return 0;

    // Extract input parameters from fuzz data
    double tempK;
    cmsCIExyY whitePoint = extractCIExyY(data, size);
    cmsCIELab Lab = extractCIELab(data, size);
    cmsCIEXYZ blackPoint;
    cmsColorSpaceSignature colorSpace = (cmsColorSpaceSignature)(*data % 256);
    data++; size--;
    int nChannels = cmsChannelsOf(colorSpace);
    cmsToneCurve** toneCurves = extractToneCurves(data, size, nChannels);

    // Call APIs with extracted parameters
    cmsHPROFILE profile1 = cmsCreateLinearizationDeviceLinkTHR(context, colorSpace, toneCurves);
    cmsTempFromWhitePoint(&tempK, &whitePoint);
    cmsDesaturateLab(&Lab, -128.0, 128.0, -128.0, 128.0);
    cmsDetectBlackPoint(&blackPoint, profile1, INTENT_PERCEPTUAL, 0);
    cmsHPROFILE profile2 = cmsCreateLab4ProfileTHR(context, &whitePoint);

    // Clean up resources
    if (profile1) cmsCloseProfile(profile1);
    if (profile2) cmsCloseProfile(profile2);
    if (toneCurves) {
        for (int i = 0; i < nChannels; ++i) free(toneCurves[i]); // Use free instead of cmsFree
        free(toneCurves); // Use free instead of cmsFree
    }
    cmsDeleteContext(context);

    return 0;
}
