#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a double from the fuzz input
double extractDouble(const uint8_t*& data, size_t& size) {
    if (size < sizeof(double)) {
        return 0.0; // Default value if not enough data
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
        memset(&xyY, 0, sizeof(cmsCIExyY)); // Default value if not enough data
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
        memset(&Lab, 0, sizeof(cmsCIELab)); // Default value if not enough data
        return Lab;
    }
    memcpy(&Lab, data, sizeof(cmsCIELab));
    data += sizeof(cmsCIELab);
    size -= sizeof(cmsCIELab);
    return Lab;
}

// Function to safely extract an array of cmsToneCurve pointers from the fuzz input
cmsToneCurve** extractToneCurves(const uint8_t*& data, size_t& size, int nChannels) {
    cmsToneCurve** curves = (cmsToneCurve**)malloc(nChannels * sizeof(cmsToneCurve*));
    if (!curves) return nullptr;

    for (int i = 0; i < nChannels; ++i) {
        if (size < sizeof(cmsToneCurve*)) {
            free(curves);
            return nullptr;
        }
        memcpy(&curves[i], data, sizeof(cmsToneCurve*));
        data += sizeof(cmsToneCurve*);
        size -= sizeof(cmsToneCurve*);
    }
    return curves;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) return 0;

    cmsHPROFILE profile = nullptr;
    cmsCIExyY whitePoint;
    cmsFloat64Number tempK;
    cmsCIELab Lab;
    cmsCIEXYZ blackPoint;
    cmsToneCurve** toneCurves = nullptr;
    int nChannels = 3; // Assuming 3 channels for simplicity

    // Extract data from fuzz input
    whitePoint = extractCIExyY(data, size);
    Lab = extractCIELab(data, size);
    toneCurves = extractToneCurves(data, size, nChannels);

    // Call cmsCreateLab4ProfileTHR
    profile = cmsCreateLab4ProfileTHR(context, &whitePoint);
    if (!profile) goto cleanup;

    // Call cmsTempFromWhitePoint
    if (!cmsTempFromWhitePoint(&tempK, &whitePoint)) goto cleanup;

    // Call cmsDesaturateLab
    if (!cmsDesaturateLab(&Lab, -128.0, 128.0, -128.0, 128.0)) goto cleanup;

    // Call cmsDetectBlackPoint
    if (!cmsDetectBlackPoint(&blackPoint, profile, INTENT_PERCEPTUAL, 0)) goto cleanup;

    // Call cmsCreateLinearizationDeviceLinkTHR
    profile = cmsCreateLinearizationDeviceLinkTHR(context, cmsSigRgbData, toneCurves);
    if (!profile) goto cleanup;

cleanup:
    // Free resources
    if (profile) cmsCloseProfile(profile);
    if (toneCurves) free(toneCurves);
    cmsDeleteContext(context);

    return 0;
}
