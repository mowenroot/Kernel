#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to create a tone curve from the fuzz input
cmsToneCurve* createToneCurveFromInput(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt16Number) * 256) {
        return nullptr; // Not enough data to create a tone curve
    }

    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(nullptr, 256, reinterpret_cast<const cmsUInt16Number*>(data));
    if (!curve) {
        return nullptr; // Failed to create tone curve
    }

    return curve;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsUInt16Number) * 256 + sizeof(cmsFloat32Number)) {
        return 0; // Not enough data to perform meaningful operations
    }

    // Create a tone curve from the fuzz input
    cmsToneCurve* curve = createToneCurveFromInput(data, size);
    if (!curve) {
        return 0; // Failed to create tone curve
    }

    // Extract the float value from the fuzz input
    cmsFloat32Number inputFloat = *reinterpret_cast<const cmsFloat32Number*>(data + sizeof(cmsUInt16Number) * 256);

    // Evaluate the tone curve with the float value
    cmsFloat32Number outputFloat = cmsEvalToneCurveFloat(curve, inputFloat);

    // Get the estimated table and its entries
    const cmsUInt16Number* estimatedTable = cmsGetToneCurveEstimatedTable(curve);
    cmsUInt32Number tableEntries = cmsGetToneCurveEstimatedTableEntries(curve);

    // Ensure the table entries are within a reasonable range
    if (tableEntries > 0 && tableEntries <= 256) {
        // Perform a sanity check on the estimated table
        for (cmsUInt32Number i = 0; i < tableEntries; ++i) {
            if (estimatedTable[i] > 65535) {
                // Invalid table entry, handle error
                cmsFreeToneCurve(curve);
                return 0;
            }
        }
    }

    // Smooth the tone curve with a lambda value derived from the fuzz input
    cmsFloat64Number lambda = static_cast<cmsFloat64Number>(data[size - 1]) / 255.0;
    if (!cmsSmoothToneCurve(curve, lambda)) {
        // Smoothing failed, handle error
        cmsFreeToneCurve(curve);
        return 0;
    }

    // Evaluate the tone curve with a 16-bit value derived from the fuzz input
    cmsUInt16Number input16 = static_cast<cmsUInt16Number>(data[size - 2]) << 8 | data[size - 3];
    cmsUInt16Number output16 = cmsEvalToneCurve16(curve, input16);

    // Free the tone curve to avoid memory leaks
    cmsFreeToneCurve(curve);

    return 0; // Return 0 to indicate successful execution
}
