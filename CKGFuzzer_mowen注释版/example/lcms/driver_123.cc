#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert a uint8_t array to a float
float safe_convert_to_float(const uint8_t* data, size_t size, size_t index) {
    if (index + sizeof(float) > size) {
        return 0.0f; // Return a default value if out of bounds
    }
    float value;
    memcpy(&value, data + index, sizeof(float));
    return value;
}

// Function to safely convert a uint8_t array to a double
double safe_convert_to_double(const uint8_t* data, size_t size, size_t index) {
    if (index + sizeof(double) > size) {
        return 0.0; // Return a default value if out of bounds
    }
    double value;
    memcpy(&value, data + index, sizeof(double));
    return value;
}

// Function to safely convert a uint8_t array to a uint32_t
uint32_t safe_convert_to_uint32(const uint8_t* data, size_t size, size_t index) {
    if (index + sizeof(uint32_t) > size) {
        return 0; // Return a default value if out of bounds
    }
    uint32_t value;
    memcpy(&value, data + index, sizeof(uint32_t));
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(float) + sizeof(double) + sizeof(uint32_t)) {
        return 0;
    }

    // Extract inputs from the fuzz data
    float input_value = safe_convert_to_float(data, size, 0);
    double lambda = safe_convert_to_double(data, size, sizeof(float));
    uint32_t table_entries = safe_convert_to_uint32(data, size, sizeof(float) + sizeof(double));

    // Create a tone curve with the specified number of entries
    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(NULL, table_entries, NULL);
    if (!curve) {
        return 0; // Failed to create tone curve
    }

    // Evaluate the tone curve
    float output_value = cmsEvalToneCurveFloat(curve, input_value);

    // Smooth the tone curve
    cmsBool smooth_result = cmsSmoothToneCurve(curve, lambda);
    if (!smooth_result) {
        cmsFreeToneCurve(curve);
        return 0; // Smoothing failed
    }

    // Check if the tone curve is monotonic
    cmsBool is_monotonic = cmsIsToneCurveMonotonic(curve);

    // Get the estimated number of table entries
    uint32_t estimated_entries = cmsGetToneCurveEstimatedTableEntries(curve);

    // Free the tone curve
    cmsFreeToneCurve(curve);

    // Return 0 to indicate success
    return 0;
}
