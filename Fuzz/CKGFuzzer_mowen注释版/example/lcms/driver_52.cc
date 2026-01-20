#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert a uint8_t array to a cmsUInt16Number array
void safeConvertToUInt16Array(const uint8_t* data, size_t size, cmsUInt16Number* out, size_t maxSize) {
    size_t count = size / 2;
    if (count > maxSize) count = maxSize;
    for (size_t i = 0; i < count; ++i) {
        out[i] = (data[i * 2] << 8) | data[i * 2 + 1];
    }
}

// Function to safely convert a uint8_t array to a cmsFloat64Number
cmsFloat64Number safeConvertToFloat64(const uint8_t* data, size_t size) {
    if (size < 8) return 0.0;
    return *reinterpret_cast<const cmsFloat64Number*>(data);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < 16) return 0;

    // Initialize variables
    cmsPipeline* lut = cmsPipelineAlloc(0, 3, 3);
    if (!lut) return 0;

    cmsStage* stage = cmsStageAllocToneCurves(0, 1, nullptr);
    if (!stage) {
        cmsPipelineFree(lut);
        return 0;
    }

    // Insert stage into pipeline
    if (!cmsPipelineInsertStage(lut, cmsAT_BEGIN, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(lut);
        return 0;
    }

    // Check if the pipeline is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(nullptr); // Passing nullptr to test error handling

    // Count the number of stages in the pipeline
    cmsUInt32Number stageCount = cmsPipelineStageCount(lut);

    // Create a tone curve and smooth it
    cmsToneCurve* toneCurve = cmsBuildGamma(0, 2.2);
    if (!toneCurve) {
        cmsPipelineFree(lut);
        return 0;
    }

    cmsFloat64Number lambda = safeConvertToFloat64(data, size);
    if (!cmsSmoothToneCurve(toneCurve, lambda)) {
        cmsFreeToneCurve(toneCurve);
        cmsPipelineFree(lut);
        return 0;
    }

    // Evaluate the pipeline with input data
    cmsUInt16Number input[3];
    cmsUInt16Number output[3];
    safeConvertToUInt16Array(data, size, input, 3);

    cmsPipelineEval16(input, output, lut);

    // Clean up
    cmsFreeToneCurve(toneCurve);
    cmsPipelineFree(lut);

    return 0;
}
