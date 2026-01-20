#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a uint32_t value from the fuzzer input
uint32_t SafeExtractUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value = *reinterpret_cast<const uint32_t*>(data + offset);
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a double value from the fuzzer input
double SafeExtractDouble(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Return a default value if not enough data
    }
    double value = *reinterpret_cast<const double*>(data + offset);
    offset += sizeof(double);
    return value;
}

// Function to safely extract a cmsColorSpaceSignature value from the fuzzer input
cmsColorSpaceSignature SafeExtractColorSpace(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsColorSpaceSignature) > size) {
        return cmsSigXYZData; // Return a default value if not enough data
    }
    cmsColorSpaceSignature value = *reinterpret_cast<const cmsColorSpaceSignature*>(data + offset);
    offset += sizeof(cmsColorSpaceSignature);
    return value;
}

// Function to safely extract a cmsHPROFILE value from the fuzzer input
cmsHPROFILE SafeExtractProfile(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsHPROFILE) > size) {
        return nullptr; // Return a default value if not enough data
    }
    cmsHPROFILE value = *reinterpret_cast<const cmsHPROFILE*>(data + offset);
    offset += sizeof(cmsHPROFILE);
    return value;
}

// Function to safely extract a cmsToneCurve* array from the fuzzer input
cmsToneCurve** SafeExtractToneCurves(const uint8_t* data, size_t size, size_t& offset, size_t count) {
    if (offset + count * sizeof(cmsToneCurve*) > size) {
        return nullptr; // Return a default value if not enough data
    }
    cmsToneCurve** curves = new cmsToneCurve*[count];
    for (size_t i = 0; i < count; ++i) {
        // Use uintptr_t to safely cast the pointer value
        curves[i] = reinterpret_cast<cmsToneCurve*>(*reinterpret_cast<const uintptr_t*>(data + offset));
        offset += sizeof(uintptr_t);
    }
    return curves;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE profiles[3] = {nullptr, nullptr, nullptr};
    cmsHTRANSFORM transform = nullptr;
    cmsToneCurve* curves[3] = {nullptr, nullptr, nullptr};

    // Extract input data
    uint32_t inputFormat = SafeExtractUInt32(data, size, offset);
    uint32_t outputFormat = SafeExtractUInt32(data, size, offset);
    uint32_t intent = SafeExtractUInt32(data, size, offset);
    uint32_t flags = SafeExtractUInt32(data, size, offset);
    double limit = SafeExtractDouble(data, size, offset);
    cmsColorSpaceSignature colorSpace = SafeExtractColorSpace(data, size, offset);

    // Create profiles and transforms
    profiles[0] = cmsCreateInkLimitingDeviceLink(colorSpace, limit);
    if (!profiles[0]) {
        return 0; // Error handling
    }

    profiles[1] = cmsCreateLinearizationDeviceLink(colorSpace, curves);
    if (!profiles[1]) {
        cmsCloseProfile(profiles[0]);
        return 0; // Error handling
    }

    profiles[2] = cmsCreateProofingTransform(profiles[0], inputFormat, profiles[1], outputFormat, profiles[1], intent, intent, flags);
    if (!profiles[2]) {
        cmsCloseProfile(profiles[0]);
        cmsCloseProfile(profiles[1]);
        return 0; // Error handling
    }

    transform = cmsCreateMultiprofileTransform(profiles, 3, inputFormat, outputFormat, intent, flags);
    if (!transform) {
        cmsCloseProfile(profiles[0]);
        cmsCloseProfile(profiles[1]);
        cmsCloseProfile(profiles[2]);
        return 0; // Error handling
    }

    // Clean up resources
    cmsDeleteTransform(transform);
    cmsCloseProfile(profiles[0]);
    cmsCloseProfile(profiles[1]);
    cmsCloseProfile(profiles[2]);

    return 0;
}
