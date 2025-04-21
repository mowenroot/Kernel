#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
const char* SafeStringCopy(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len > size) return nullptr;
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += max_len;
    return str;
}

// Function to safely get a uint16_t value from fuzz input
cmsUInt16Number SafeGetUInt16(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsUInt16Number) > size) return 0;
    cmsUInt16Number value = *reinterpret_cast<const cmsUInt16Number*>(data + offset);
    offset += sizeof(cmsUInt16Number);
    return value;
}

// Function to safely get a double value from fuzz input
cmsFloat64Number SafeGetFloat64(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(cmsFloat64Number) > size) return 0.0;
    cmsFloat64Number value = *reinterpret_cast<const cmsFloat64Number*>(data + offset);
    offset += sizeof(cmsFloat64Number);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    if (!mlu) return 0;

    // Safely extract input parameters
    const char* languageCode = SafeStringCopy(data, size, offset, 3);
    const char* countryCode = SafeStringCopy(data, size, offset, 3);
    const char* asciiString = SafeStringCopy(data, size, offset, size - offset);
    cmsUInt16Number inputValue = SafeGetUInt16(data, size, offset);
    cmsFloat64Number lambda = SafeGetFloat64(data, size, offset);
    cmsFloat64Number precision = SafeGetFloat64(data, size, offset);

    // Ensure all parameters are valid
    if (!languageCode || !countryCode || !asciiString) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Call cmsMLUsetASCII
    if (!cmsMLUsetASCII(mlu, languageCode, countryCode, asciiString)) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Create and initialize a tone curve
    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(NULL, 256, nullptr);
    if (!curve) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Call cmsEvalToneCurve16
    cmsUInt16Number outputValue = cmsEvalToneCurve16(curve, inputValue);

    // Call cmsSmoothToneCurve
    if (!cmsSmoothToneCurve(curve, lambda)) {
        cmsFreeToneCurve(curve);
        cmsMLUfree(mlu);
        return 0;
    }

    // Call cmsEstimateGamma
    cmsFloat64Number gamma = cmsEstimateGamma(curve, precision);

    // Call cmsIsToneCurveMonotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(curve);

    // Clean up resources
    cmsFreeToneCurve(curve);
    cmsMLUfree(mlu);

    return 0;
}
