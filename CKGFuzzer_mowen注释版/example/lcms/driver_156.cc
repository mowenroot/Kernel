#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory for a buffer
template <typename T>
T* safe_malloc(size_t size) {
    if (size == 0) return nullptr;
    T* ptr = static_cast<T*>(malloc(size * sizeof(T)));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free allocated memory
template <typename T>
void safe_free(T* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data into a buffer
template <typename T>
void safe_copy(T* dest, const T* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size * sizeof(T));
    }
}

// Function to safely convert uint8_t data to cmsFloat32Number
cmsFloat32Number* convert_to_float32(const uint8_t* data, size_t size) {
    if (size % sizeof(cmsFloat32Number) != 0) {
        return nullptr;
    }
    size_t count = size / sizeof(cmsFloat32Number);
    cmsFloat32Number* result = safe_malloc<cmsFloat32Number>(count);
    for (size_t i = 0; i < count; ++i) {
        result[i] = static_cast<cmsFloat32Number>(data[i]);
    }
    return result;
}

// Function to safely convert uint8_t data to cmsUInt16Number
cmsUInt16Number* convert_to_uint16(const uint8_t* data, size_t size) {
    if (size % sizeof(cmsUInt16Number) != 0) {
        return nullptr;
    }
    size_t count = size / sizeof(cmsUInt16Number);
    cmsUInt16Number* result = safe_malloc<cmsUInt16Number>(count);
    for (size_t i = 0; i < count; ++i) {
        result[i] = static_cast<cmsUInt16Number>(data[i]);
    }
    return result;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsFloat32Number) * 2) {
        return 0;
    }

    // Create a pipeline for testing
    cmsPipeline* lut = cmsPipelineAlloc(0, 3, 3);
    if (!lut) {
        return 0;
    }

    // Convert input data to appropriate types
    cmsFloat32Number* input_float = convert_to_float32(data, size);
    cmsUInt16Number* input_uint16 = convert_to_uint16(data, size);

    // Ensure conversion was successful
    if (!input_float || !input_uint16) {
        cmsPipelineFree(lut);
        safe_free(input_float);
        safe_free(input_uint16);
        return 0;
    }

    // Allocate output buffers
    cmsFloat32Number* output_float = safe_malloc<cmsFloat32Number>(3);
    cmsUInt16Number* output_uint16 = safe_malloc<cmsUInt16Number>(3);

    // Test cmsPipelineEvalFloat
    cmsPipelineEvalFloat(input_float, output_float, lut);

    // Test cmsPipelineEval16
    cmsPipelineEval16(input_uint16, output_uint16, lut);

    // Test cmsPipelineEvalReverseFloat
    cmsFloat32Number target[3] = {1.0f, 1.0f, 1.0f};
    cmsFloat32Number result[3];
    cmsPipelineEvalReverseFloat(target, result, input_float, lut);

    // Test cmsPipelineCheckAndRetreiveStages
    cmsStage* stage_ptr = nullptr;
    cmsPipelineCheckAndRetreiveStages(lut, 1, cmsSigCurveSetElemType, &stage_ptr);

    // Test cmsPipelineCat
    cmsPipeline* lut2 = cmsPipelineAlloc(0, 3, 3);
    if (lut2) {
        cmsPipelineCat(lut, lut2);
        cmsPipelineFree(lut2);
    }

    // Free allocated resources
    cmsPipelineFree(lut);
    safe_free(input_float);
    safe_free(input_uint16);
    safe_free(output_float);
    safe_free(output_uint16);

    return 0;
}
