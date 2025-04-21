#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits> // Include the limits header to use std::numeric_limits

// Function to safely allocate memory
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely copy memory
void safeMemcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely cast and check size
template <typename T>
T safeCast(size_t value) {
    if (value > std::numeric_limits<T>::max()) { // Use std::numeric_limits
        fprintf(stderr, "Value out of range for type\n");
        exit(EXIT_FAILURE);
    }
    return static_cast<T>(value);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < sizeof(cmsUInt32Number) * 4) {
        return 0;
    }

    // Extract necessary data from the fuzz input
    cmsUInt32Number intent = safeCast<cmsUInt32Number>(data[0]);
    cmsUInt32Number direction = safeCast<cmsUInt32Number>(data[1]);
    cmsUInt32Number inputChannels = safeCast<cmsUInt32Number>(data[2]);
    cmsUInt32Number outputChannels = safeCast<cmsUInt32Number>(data[3]);

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0;
    }

    // Check if the profile supports the specified CLUT
    cmsBool isCLUTSupported = cmsIsCLUT(hProfile, intent, direction);
    if (isCLUTSupported) {
        // Create a pipeline for further operations
        cmsPipeline* lut = cmsPipelineAlloc(NULL, inputChannels, outputChannels);
        if (!lut) {
            cmsCloseProfile(hProfile);
            return 0;
        }

        // Get the number of input channels from the pipeline
        cmsUInt32Number pipelineInputChannels = cmsPipelineInputChannels(lut);

        // Allocate memory for input and output buffers
        cmsUInt16Number* inBuffer = (cmsUInt16Number*)safeMalloc(pipelineInputChannels * sizeof(cmsUInt16Number));
        cmsUInt16Number* outBuffer = (cmsUInt16Number*)safeMalloc(outputChannels * sizeof(cmsUInt16Number));

        // Copy fuzz input data to the input buffer
        safeMemcpy(inBuffer, data + sizeof(cmsUInt32Number) * 4, pipelineInputChannels * sizeof(cmsUInt16Number));

        // Evaluate the pipeline with the input buffer
        cmsPipelineEval16(inBuffer, outBuffer, lut);

        // Free the pipeline and buffers
        cmsPipelineFree(lut);
        free(inBuffer);
        free(outBuffer);
    }

    // Detect Total Area Coverage (TAC) for the profile
    cmsFloat64Number tac = cmsDetectTAC(hProfile);

    // Close the profile handle
    cmsCloseProfile(hProfile);

    return 0;
}
