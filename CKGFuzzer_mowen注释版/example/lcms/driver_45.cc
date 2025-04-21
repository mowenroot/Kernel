#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory for a cmsPipeline
cmsPipeline* SafeCmsPipelineAlloc(cmsContext ContextID) {
    cmsPipeline* lut = cmsPipelineAlloc(ContextID, 3, 3);
    if (!lut) {
        fprintf(stderr, "Failed to allocate cmsPipeline\n");
        exit(1);
    }
    return lut;
}

// Function to safely allocate memory for a cmsStage
cmsStage* SafeCmsStageAlloc(cmsContext ContextID) {
    cmsStage* stage = cmsStageAllocIdentity(ContextID, 3); // Corrected to use cmsStageAllocIdentity
    if (!stage) {
        fprintf(stderr, "Failed to allocate cmsStage\n");
        exit(1);
    }
    return stage;
}

// Function to safely allocate memory for a cmsFloat32Number array
cmsFloat32Number* SafeAllocFloat32Array(size_t size) {
    cmsFloat32Number* arr = (cmsFloat32Number*)malloc(size * sizeof(cmsFloat32Number));
    if (!arr) {
        fprintf(stderr, "Failed to allocate cmsFloat32Number array\n");
        exit(1);
    }
    return arr;
}

// Function to safely allocate memory for a cmsUInt16Number array
cmsUInt16Number* SafeAllocUInt16Array(size_t size) {
    cmsUInt16Number* arr = (cmsUInt16Number*)malloc(size * sizeof(cmsUInt16Number));
    if (!arr) {
        fprintf(stderr, "Failed to allocate cmsUInt16Number array\n");
        exit(1);
    }
    return arr;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < 16) return 0;

    // Initialize the cmsContext
    cmsContext ContextID = cmsCreateContext(NULL, NULL);
    if (!ContextID) {
        fprintf(stderr, "Failed to create cmsContext\n");
        return 0;
    }

    // Allocate a cmsPipeline
    std::unique_ptr<cmsPipeline, void(*)(cmsPipeline*)> lut(SafeCmsPipelineAlloc(ContextID), cmsPipelineFree);

    // Allocate a cmsStage
    std::unique_ptr<cmsStage, void(*)(cmsStage*)> stage(SafeCmsStageAlloc(ContextID), cmsStageFree);

    // Insert the stage into the pipeline
    if (!cmsPipelineInsertStage(lut.get(), cmsAT_BEGIN, stage.get())) {
        fprintf(stderr, "Failed to insert stage into pipeline\n");
        return 0;
    }

    // Unlink the stage from the pipeline
    cmsStage* unlinkedStage = nullptr;
    cmsPipelineUnlinkStage(lut.get(), cmsAT_BEGIN, &unlinkedStage);
    if (unlinkedStage) {
        cmsStageFree(unlinkedStage);
    }

    // Allocate input and output buffers
    cmsFloat32Number* inFloat = SafeAllocFloat32Array(3);
    cmsFloat32Number* outFloat = SafeAllocFloat32Array(3);
    cmsUInt16Number* in16 = SafeAllocUInt16Array(3);
    cmsUInt16Number* out16 = SafeAllocUInt16Array(3);

    // Copy input data to the buffers
    memcpy(inFloat, data, 3 * sizeof(cmsFloat32Number));
    memcpy(in16, data + 3 * sizeof(cmsFloat32Number), 3 * sizeof(cmsUInt16Number));

    // Evaluate the pipeline with float inputs
    cmsPipelineEvalFloat(inFloat, outFloat, lut.get());

    // Evaluate the pipeline with 16-bit inputs
    cmsPipelineEval16(in16, out16, lut.get());

    // Evaluate the reverse pipeline with float inputs
    cmsFloat32Number target[3] = {1.0f, 1.0f, 1.0f};
    cmsFloat32Number result[3];
    cmsPipelineEvalReverseFloat(target, result, inFloat, lut.get());

    // Free allocated memory
    free(inFloat);
    free(outFloat);
    free(in16);
    free(out16);

    // Destroy the cmsContext
    cmsDeleteContext(ContextID);

    return 0;
}
