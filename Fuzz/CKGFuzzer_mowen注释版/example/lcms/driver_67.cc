#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to create a cmsToneCurve from the fuzz input data
cmsToneCurve* createToneCurveFromInput(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt16Number) * 256) {
        return nullptr; // Not enough data to create a valid tone curve
    }

    cmsContext contextID = cmsCreateContext(nullptr, nullptr);
    if (!contextID) {
        return nullptr; // Failed to create context
    }

    // Use cmsBuildTabulatedToneCurve16 to create the tone curve
    cmsToneCurve* curve = cmsBuildTabulatedToneCurve16(contextID, 256, reinterpret_cast<const cmsUInt16Number*>(data));
    if (!curve) {
        cmsDeleteContext(contextID);
        return nullptr; // Failed to create tone curve
    }

    return curve;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Ensure we have enough data to create a tone curve
    if (size < sizeof(cmsUInt16Number) * 256) {
        return 0; // Not enough data to proceed
    }

    // Create a tone curve from the input data
    cmsToneCurve* curve = createToneCurveFromInput(data, size);
    if (!curve) {
        return 0; // Failed to create tone curve
    }

    // Retrieve the estimated table and its entries
    const cmsUInt16Number* estimatedTable = cmsGetToneCurveEstimatedTable(curve);
    cmsUInt32Number tableEntries = cmsGetToneCurveEstimatedTableEntries(curve);

    // Ensure the estimated table and entries are valid
    if (!estimatedTable || tableEntries == 0) {
        cmsFreeToneCurve(curve);
        return 0; // Invalid estimated table or entries
    }

    // Evaluate the tone curve with a float value derived from the input data
    cmsFloat32Number inputFloat = static_cast<cmsFloat32Number>(data[0]) / 255.0f;
    cmsFloat32Number outputFloat = cmsEvalToneCurveFloat(curve, inputFloat);

    // Evaluate the tone curve with a 16-bit value derived from the input data
    cmsUInt16Number input16 = static_cast<cmsUInt16Number>(data[1]) << 8 | data[2];
    cmsUInt16Number output16 = cmsEvalToneCurve16(curve, input16);

    // Smooth the tone curve with a lambda value derived from the input data
    cmsFloat64Number lambda = static_cast<cmsFloat64Number>(data[3]) / 255.0;
    cmsBool smoothingResult = cmsSmoothToneCurve(curve, lambda);

    // Free the tone curve to avoid memory leaks
    cmsFreeToneCurve(curve);

    return 0; // Return 0 to indicate successful execution
}
