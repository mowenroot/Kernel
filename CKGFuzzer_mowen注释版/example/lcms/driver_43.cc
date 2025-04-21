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
    if (memcpy(dest, src, n) != dest) {
        fprintf(stderr, "Memory copy failed\n");
        exit(EXIT_FAILURE);
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
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsUInt32Number) * 3) {
        return 0;
    }

    // Extract parameters from the fuzz input
    cmsUInt32Number intent = *reinterpret_cast<const cmsUInt32Number*>(data);
    cmsUInt32Number direction = *reinterpret_cast<const cmsUInt32Number*>(data + sizeof(cmsUInt32Number));
    cmsUInt32Number profileClass = *reinterpret_cast<const cmsUInt32Number*>(data + 2 * sizeof(cmsUInt32Number));

    // Create a dummy profile for testing
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0;
    }

    // Set the profile class
    cmsSetDeviceClass(hProfile, static_cast<cmsProfileClassSignature>(profileClass));

    // Test cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, intent, direction);

    // Create two dummy pipelines for testing
    cmsPipeline* lut1 = cmsPipelineAlloc(NULL, 3, 3);
    cmsPipeline* lut2 = cmsPipelineAlloc(NULL, 3, 3);
    if (!lut1 || !lut2) {
        cmsCloseProfile(hProfile);
        cmsPipelineFree(lut1);
        cmsPipelineFree(lut2);
        return 0;
    }

    // Test cmsPipelineCat
    cmsBool pipelineCatResult = cmsPipelineCat(lut1, lut2);

    // Test cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Test cmsPipelineUnlinkStage
    cmsStage* unlinkedStage = nullptr;
    cmsPipelineUnlinkStage(lut1, cmsAT_BEGIN, &unlinkedStage);
    if (unlinkedStage) {
        cmsStageFree(unlinkedStage);
    }

    // Test cmsPipelineInsertStage
    // Corrected the function call to cmsStageAllocCLut16bit by providing the correct number of arguments
    cmsStage* newStage = cmsStageAllocCLut16bit(NULL, 3, 3, 3, nullptr);
    if (newStage) {
        cmsPipelineInsertStage(lut1, cmsAT_BEGIN, newStage);
    }

    // Clean up
    cmsPipelineFree(lut1);
    cmsPipelineFree(lut2);
    cmsCloseProfile(hProfile);

    return 0;
}
