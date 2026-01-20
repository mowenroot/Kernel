#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory and check for allocation failures
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely copy data and check for buffer overflows
void safe_copy(void* dest, const void* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely cast and access data
template <typename T>
T safe_cast(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(T) > size) {
        fprintf(stderr, "Buffer overflow detected\n");
        exit(1);
    }
    T value = *reinterpret_cast<const T*>(data + offset);
    offset += sizeof(T);
    return value;
}

// Function to safely access a buffer
template <typename T>
T* safe_buffer(const uint8_t* data, size_t& offset, size_t size, size_t buffer_size) {
    if (offset + buffer_size > size) {
        fprintf(stderr, "Buffer overflow detected\n");
        exit(1);
    }
    T* buffer = reinterpret_cast<T*>(const_cast<uint8_t*>(data + offset));
    offset += buffer_size;
    return buffer;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to perform meaningful operations
    if (size < sizeof(cmsUInt16Number) * 2 + sizeof(cmsFloat32Number) * 2) {
        return 0;
    }

    // Initialize variables and structures
    size_t offset = 0;
    cmsPipeline* lut = cmsPipelineAlloc(0, 3, 3);
    if (!lut) {
        return 0;
    }

    // Create a stage to insert into the pipeline
    cmsStage* stage = cmsStageAllocIdentity(0, 3);
    if (!stage) {
        cmsPipelineFree(lut);
        return 0;
    }

    // Insert the stage into the pipeline
    if (!cmsPipelineInsertStage(lut, cmsAT_BEGIN, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(lut);
        return 0;
    }

    // Unlink the stage from the pipeline
    cmsStage* unlinked_stage = nullptr;
    cmsPipelineUnlinkStage(lut, cmsAT_BEGIN, &unlinked_stage);
    if (unlinked_stage) {
        cmsStageFree(unlinked_stage);
    }

    // Prepare input and output buffers
    cmsUInt16Number in16[3];
    cmsFloat32Number in32[3];
    cmsFloat32Number out32[3];
    cmsUInt16Number out16[3];

    // Extract input data from fuzzer input
    for (int i = 0; i < 3; ++i) {
        in16[i] = safe_cast<cmsUInt16Number>(data, offset, size);
        in32[i] = safe_cast<cmsFloat32Number>(data, offset, size);
    }

    // Evaluate the pipeline with 16-bit input
    cmsPipelineEval16(in16, out16, lut);

    // Evaluate the pipeline with 32-bit input
    cmsPipelineEvalFloat(in32, out32, lut);

    // Evaluate the reverse pipeline with 32-bit input
    cmsFloat32Number target[3];
    cmsFloat32Number result[3];
    cmsFloat32Number hint[3];

    // Extract target and hint data from fuzzer input
    for (int i = 0; i < 3; ++i) {
        target[i] = safe_cast<cmsFloat32Number>(data, offset, size);
        hint[i] = safe_cast<cmsFloat32Number>(data, offset, size);
    }

    // Evaluate the reverse pipeline
    cmsPipelineEvalReverseFloat(target, result, hint, lut);

    // Free the pipeline and associated resources
    cmsPipelineFree(lut);

    return 0;
}
