#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory and return a unique_ptr
template <typename T>
std::unique_ptr<T[]> safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size * sizeof(T)));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return std::unique_ptr<T[]>(ptr);
}

// Function to safely allocate memory and return a unique_ptr
template <typename T>
std::unique_ptr<T> safe_malloc_single() {
    T* ptr = static_cast<T*>(malloc(sizeof(T)));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return std::unique_ptr<T>(ptr);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsFloat32Number) * 2 + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract parameters from the fuzz input
    const cmsFloat32Number* input = reinterpret_cast<const cmsFloat32Number*>(data);
    cmsFloat32Number* output = safe_malloc<cmsFloat32Number>(1).get();
    cmsFloat64Number lambda = *reinterpret_cast<const cmsFloat64Number*>(data + sizeof(cmsFloat32Number));

    // Create an array of parameters for the tone curve
    cmsFloat64Number params[256];
    for (size_t i = 0; i < 256; ++i) {
        params[i] = static_cast<cmsFloat64Number>(input[i % 2]);
    }

    // Create a tone curve
    cmsToneCurve* toneCurve = cmsBuildParametricToneCurve(NULL, 4, params);
    if (!toneCurve) {
        return 0;
    }

    // Smooth the tone curve
    if (!cmsSmoothToneCurve(toneCurve, lambda)) {
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    // Check if the tone curve is monotonic
    if (!cmsIsToneCurveMonotonic(toneCurve)) {
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    // Create a pipeline
    cmsPipeline* pipeline = cmsPipelineAlloc(NULL, 3, 3);
    if (!pipeline) {
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    cmsStage* stage = cmsStageAllocToneCurves(NULL, 1, &toneCurve);
    if (!stage) {
        cmsPipelineFree(pipeline);
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    if (cmsPipelineInsertStage(pipeline, cmsAT_END, stage) != TRUE) {
        cmsStageFree(stage);
        cmsPipelineFree(pipeline);
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    // Evaluate the pipeline
    cmsPipelineEvalFloat(input, output, pipeline);

    // Clean up
    cmsPipelineFree(pipeline);
    cmsFreeToneCurve(toneCurve);

    return 0;
}
