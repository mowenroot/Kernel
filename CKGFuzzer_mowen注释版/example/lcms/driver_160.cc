#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely copy data
void safeMemcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely free memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(cmsUInt32Number) * 3) {
        return 0;
    }

    // Extract input channels, output channels, and stage count from the fuzz input
    cmsUInt32Number inputChannels = *reinterpret_cast<const cmsUInt32Number*>(data);
    cmsUInt32Number outputChannels = *reinterpret_cast<const cmsUInt32Number*>(data + sizeof(cmsUInt32Number));
    cmsUInt32Number stageCount = *reinterpret_cast<const cmsUInt32Number*>(data + 2 * sizeof(cmsUInt32Number));

    // Create a new cmsPipeline
    cmsPipeline* lut = cmsPipelineAlloc(NULL, inputChannels, outputChannels);
    if (!lut) {
        return 0;
    }

    // Insert stages into the pipeline
    for (cmsUInt32Number i = 0; i < stageCount; ++i) {
        cmsStage* stage = cmsStageAllocToneCurves(NULL, 1, NULL);
        if (!stage) {
            cmsPipelineFree(lut);
            return 0;
        }
        cmsPipelineInsertStage(lut, cmsAT_END, stage);
    }

    // Check the number of stages in the pipeline
    cmsUInt32Number actualStageCount = cmsPipelineStageCount(lut);
    if (actualStageCount != stageCount) {
        cmsPipelineFree(lut);
        return 0;
    }

    // Check the number of input and output channels
    cmsUInt32Number actualInputChannels = cmsPipelineInputChannels(lut);
    cmsUInt32Number actualOutputChannels = cmsPipelineOutputChannels(lut);
    if (actualInputChannels != inputChannels || actualOutputChannels != outputChannels) {
        cmsPipelineFree(lut);
        return 0;
    }

    // Create a tone curve and check if it is monotonic
    cmsToneCurve* toneCurve = cmsBuildGamma(NULL, 2.2);
    if (!toneCurve) {
        cmsPipelineFree(lut);
        return 0;
    }
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);
    cmsFreeToneCurve(toneCurve);

    // Free the pipeline
    cmsPipelineFree(lut);

    return 0;
}
