#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a float from the fuzz input
float safe_extract_float(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Default value if not enough data
    }
    float value;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return value;
}

// Function to safely extract an integer from the fuzz input
int safe_extract_int(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(int) > size) {
        return 0; // Default value if not enough data
    }
    int value;
    memcpy(&value, data + offset, sizeof(int));
    offset += sizeof(int);
    return value;
}

// Function to safely extract a double from the fuzz input
double safe_extract_double(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Default value if not enough data
    }
    double value;
    memcpy(&value, data + offset, sizeof(double));
    offset += sizeof(double);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsToneCurve* curve = nullptr;
    cmsCIEXYZ blackPoint;
    cmsCIELab lab;
    cmsUInt16Number encodedLab[3];

    // Extract inputs from fuzz data
    float inputValue = safe_extract_float(data, size, offset);
    double lambda = safe_extract_double(data, size, offset);
    int intent = safe_extract_int(data, size, offset);
    int dwFlags = safe_extract_int(data, size, offset);

    // Create a tone curve
    curve = cmsBuildGamma(nullptr, 2.2);
    if (!curve) {
        return 0; // Failed to create tone curve
    }

    // Evaluate the tone curve
    cmsEvalToneCurveFloat(curve, inputValue);

    // Smooth the tone curve
    cmsSmoothToneCurve(curve, lambda);

    // Check if the tone curve is monotonic
    cmsIsToneCurveMonotonic(curve);

    // Detect black point
    cmsDetectBlackPoint(&blackPoint, nullptr, intent, dwFlags);

    // Convert float Lab to encoded Lab
    lab.L = safe_extract_float(data, size, offset);
    lab.a = safe_extract_float(data, size, offset);
    lab.b = safe_extract_float(data, size, offset);
    cmsFloat2LabEncodedV2(encodedLab, &lab);

    // Clean up
    if (curve) {
        cmsFreeToneCurve(curve);
    }

    return 0;
}
