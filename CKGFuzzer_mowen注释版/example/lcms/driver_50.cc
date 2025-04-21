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

    // Initialize variables
    cmsContext context = NULL; // Added context variable
    cmsUInt32Number inputChannels = *((cmsUInt32Number*)data);
    cmsUInt32Number outputChannels = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number)));
    cmsPipeline* lut = cmsPipelineAlloc(context, inputChannels, outputChannels); // Corrected function call
    if (!lut) {
        return 0;
    }

    cmsToneCurve* toneCurve = cmsBuildTabulatedToneCurve16(NULL, 2, (cmsUInt16Number*)data);
    if (!toneCurve) {
        cmsPipelineFree(lut);
        return 0;
    }

    // Extract input channels, output channels, and stage count from the fuzz input
    cmsUInt32Number stageCount = *((cmsUInt32Number*)(data + 2 * sizeof(cmsUInt32Number)));

    // Insert stages into the pipeline
    for (cmsUInt32Number i = 0; i < stageCount; ++i) {
        cmsStage* stage = cmsStageAllocToneCurves(NULL, 1, &toneCurve);
        if (!stage) {
            cmsPipelineFree(lut);
            cmsFreeToneCurve(toneCurve);
            return 0;
        }
        if (!cmsPipelineInsertStage(lut, cmsAT_END, stage)) {
            cmsStageFree(stage);
            cmsPipelineFree(lut);
            cmsFreeToneCurve(toneCurve);
            return 0;
        }
    }

    // Check if the tone curve is monotonic
    cmsBool isMonotonic = cmsIsToneCurveMonotonic(toneCurve);

    // Retrieve and validate pipeline properties
    cmsUInt32Number retrievedInputChannels = cmsPipelineInputChannels(lut);
    cmsUInt32Number retrievedOutputChannels = cmsPipelineOutputChannels(lut);
    cmsUInt32Number retrievedStageCount = cmsPipelineStageCount(lut);

    // Ensure the retrieved values match the expected values
    if (retrievedInputChannels != inputChannels ||
        retrievedOutputChannels != outputChannels ||
        retrievedStageCount != stageCount) {
        cmsPipelineFree(lut);
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    // Free allocated resources
    cmsPipelineFree(lut);
    cmsFreeToneCurve(toneCurve);

    return 0;
}
