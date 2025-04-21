#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to create a cmsToneCurve from the fuzz input data
cmsToneCurve* createToneCurveFromData(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt16Number) * 256) {
        return nullptr; // Not enough data to create a valid tone curve
    }

    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(nullptr, 256, reinterpret_cast<const cmsUInt16Number*>(data));
    if (!curve) {
        return nullptr; // Failed to create the tone curve
    }

    return curve;
}

// Function to safely extract a float value from the fuzz input data
bool extractFloatFromData(const uint8_t* data, size_t size, size_t& offset, cmsFloat32Number& value) {
    if (offset + sizeof(cmsFloat32Number) > size) {
        return false; // Not enough data to extract a float
    }

    value = *reinterpret_cast<const cmsFloat32Number*>(data + offset);
    offset += sizeof(cmsFloat32Number);
    return true;
}

// Function to safely extract a double value from the fuzz input data
bool extractDoubleFromData(const uint8_t* data, size_t size, size_t& offset, cmsFloat64Number& value) {
    if (offset + sizeof(cmsFloat64Number) > size) {
        return false; // Not enough data to extract a double
    }

    value = *reinterpret_cast<const cmsFloat64Number*>(data + offset);
    offset += sizeof(cmsFloat64Number);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsUInt16Number) * 256 + sizeof(cmsFloat32Number) + sizeof(cmsFloat64Number)) {
        return 0; // Not enough data to perform meaningful operations
    }

    // Create a tone curve from the input data
    std::unique_ptr<cmsToneCurve, void(*)(cmsToneCurve*)> curve(createToneCurveFromData(data, size), cmsFreeToneCurve);
    if (!curve) {
        return 0; // Failed to create the tone curve
    }

    // Extract a float value for cmsEvalToneCurveFloat
    size_t offset = sizeof(cmsUInt16Number) * 256;
    cmsFloat32Number floatValue;
    if (!extractFloatFromData(data, size, offset, floatValue)) {
        return 0; // Failed to extract float value
    }

    // Extract a double value for cmsSmoothToneCurve
    cmsFloat64Number doubleValue;
    if (!extractDoubleFromData(data, size, offset, doubleValue)) {
        return 0; // Failed to extract double value
    }

    // Call cmsEvalToneCurveFloat
    cmsFloat32Number result = cmsEvalToneCurveFloat(curve.get(), floatValue);

    // Call cmsSmoothToneCurve
    if (!cmsSmoothToneCurve(curve.get(), doubleValue)) {
        return 0; // Smoothing failed
    }

    // Call cmsIsToneCurveMultisegment
    bool isMultisegment = cmsIsToneCurveMultisegment(curve.get());

    // Call cmsIsToneCurveMonotonic
    bool isMonotonic = cmsIsToneCurveMonotonic(curve.get());

    // Call cmsIsToneCurveDescending
    bool isDescending = cmsIsToneCurveDescending(curve.get());

    // Call cmsIsToneCurveLinear
    bool isLinear = cmsIsToneCurveLinear(curve.get());

    // Ensure all operations completed successfully
    if (result < 0.0f || result > 1.0f || !isMonotonic || !isLinear) {
        return 0; // Invalid result or curve properties
    }

    return 0; // Success
}
