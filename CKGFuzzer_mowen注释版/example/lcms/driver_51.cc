#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to create a dummy cmsStage for testing purposes
cmsStage* CreateDummyStage() {
    // Allocate memory for the dummy stage using cmsStageAllocIdentity
    cmsStage* dummyStage = cmsStageAllocIdentity(0, 1);
    if (!dummyStage) {
        return nullptr;
    }
    // No need to initialize dummyStage->Next since cmsStageAllocIdentity handles it
    return dummyStage;
}

// Function to free a dummy cmsStage
void FreeDummyStage(cmsStage* stage) {
    if (stage) {
        cmsStageFree(stage);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < 8) {
        return 0;
    }

    // Create a cmsPipeline object
    cmsPipeline* pipeline = cmsPipelineAlloc(0, 3, 3);
    if (!pipeline) {
        return 0;
    }

    // Create a dummy stage for insertion
    cmsStage* dummyStage = CreateDummyStage();
    if (!dummyStage) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Insert the dummy stage at the beginning of the pipeline
    if (!cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, dummyStage)) {
        FreeDummyStage(dummyStage);
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Unlink the stage from the beginning of the pipeline
    cmsStage* unlinkedStage = nullptr;
    cmsPipelineUnlinkStage(pipeline, cmsAT_BEGIN, &unlinkedStage);
    if (unlinkedStage) {
        FreeDummyStage(unlinkedStage);
    }

    // Set the SaveAs8bits flag based on the input data
    cmsBool saveAs8Bits = (data[0] % 2 == 0) ? TRUE : FALSE;
    cmsPipelineSetSaveAs8bitsFlag(pipeline, saveAs8Bits);

    // Evaluate the pipeline with dummy input data
    cmsUInt16Number input[3] = {data[1], data[2], data[3]};
    cmsUInt16Number output[3];
    cmsPipelineEval16(input, output, pipeline);

    // Count the number of stages in the pipeline
    cmsUInt32Number stageCount = cmsPipelineStageCount(pipeline);

    // Free the pipeline and all associated resources
    cmsPipelineFree(pipeline);

    return 0;
}
