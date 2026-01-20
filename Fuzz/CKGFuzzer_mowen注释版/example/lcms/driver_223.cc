#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to create a tone curve from the fuzz input data
cmsToneCurve* createToneCurveFromData(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt16Number) * 256) {
        return nullptr; // Not enough data to create a tone curve
    }

    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(nullptr, 256, reinterpret_cast<const cmsUInt16Number*>(data));
    return curve;
}

// Function to create a profile from the fuzz input data
cmsHPROFILE createProfileFromData(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsColorSpaceSignature)) {
        return nullptr; // Not enough data to create a profile
    }

    cmsColorSpaceSignature colorSpace = static_cast<cmsColorSpaceSignature>(*reinterpret_cast<const uint32_t*>(data));
    cmsHPROFILE profile = cmsCreateProfilePlaceholder(nullptr);
    if (profile) {
        cmsSetColorSpace(profile, colorSpace);
    }
    return profile;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsUInt16Number) * 256 + sizeof(cmsColorSpaceSignature)) {
        return 0; // Not enough data to proceed
    }

    // Create a tone curve from the fuzz input data
    std::unique_ptr<cmsToneCurve, void(*)(cmsToneCurve*)> curve(createToneCurveFromData(data, size), [](cmsToneCurve* c) { if (c) cmsFreeToneCurve(c); });
    if (!curve) {
        return 0; // Failed to create tone curve
    }

    // Create a profile from the fuzz input data
    std::unique_ptr<void, void(*)(void*)> profile(createProfileFromData(data + sizeof(cmsUInt16Number) * 256, size - sizeof(cmsUInt16Number) * 256), [](void* p) { if (p) cmsCloseProfile(static_cast<cmsHPROFILE>(p)); });
    if (!profile) {
        return 0; // Failed to create profile
    }

    // Extract the color space from the profile
    cmsColorSpaceSignature colorSpace = cmsGetColorSpace(static_cast<cmsHPROFILE>(profile.get()));

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(static_cast<cmsHPROFILE>(profile.get()));

    // Smooth the tone curve
    cmsBool smoothingResult = cmsSmoothToneCurve(curve.get(), 0.5);

    // Estimate gamma from the tone curve
    cmsFloat64Number gammaEstimate = cmsEstimateGamma(curve.get(), 0.01);

    // Evaluate the tone curve at a specific point
    cmsUInt16Number evalResult = cmsEvalToneCurve16(curve.get(), 0x8000);

    // Ensure all operations completed successfully
    if (colorSpace == cmsSigXYZData && isMatrixShaper && smoothingResult && gammaEstimate != -1.0 && evalResult != 0) {
        // All operations were successful
    }

    return 0; // Return 0 to indicate successful execution
}
