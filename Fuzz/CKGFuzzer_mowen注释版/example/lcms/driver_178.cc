#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory and handle errors
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely free memory
template <typename T>
void safe_free(T* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data with bounds checking
void safe_copy(void* dest, const void* src, size_t size) {
    if (src && dest && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely cast and check size
template <typename T>
T safe_cast(size_t value, const char* type_name) {
    if (value > std::numeric_limits<T>::max()) {
        fprintf(stderr, "Value too large for type %s\n", type_name);
        exit(1);
    }
    return static_cast<T>(value);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < sizeof(cmsFloat32Number) * 2) {
        return 0;
    }

    // Initialize variables
    cmsToneCurve* toneCurve = nullptr;
    cmsPipeline* pipeline = nullptr;
    cmsUInt32Number clutPoints[cmsMAXCHANNELS] = {0};
    cmsFloat32Number inFloat[cmsMAXCHANNELS] = {0};
    cmsFloat32Number outFloat[cmsMAXCHANNELS] = {0};
    cmsUInt16Number in16[cmsMAXCHANNELS] = {0};
    cmsUInt16Number out16[cmsMAXCHANNELS] = {0};
    cmsFloat64Number lambda = 0.0;
    cmsUInt32Number nInputs = 0;
    cmsBool success = FALSE;

    // Derive API inputs from fuzz driver inputs
    size_t offset = 0;
    cmsFloat32Number value = *reinterpret_cast<const cmsFloat32Number*>(data + offset);
    offset += sizeof(cmsFloat32Number);

    // Create a tone curve
    toneCurve = cmsBuildTabulatedToneCurveFloat(nullptr, 256, reinterpret_cast<const cmsFloat32Number*>(data + offset));
    if (!toneCurve) {
        return 0;
    }
    offset += sizeof(cmsFloat32Number) * 256;

    // Evaluate the tone curve
    cmsEvalToneCurveFloat(toneCurve, value);

    // Create a pipeline
    pipeline = cmsPipelineAlloc(nullptr, 3, 3);
    if (!pipeline) {
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    // Evaluate the pipeline with float values
    safe_copy(inFloat, data + offset, sizeof(cmsFloat32Number) * 3);
    offset += sizeof(cmsFloat32Number) * 3;
    cmsPipelineEvalFloat(inFloat, outFloat, pipeline);

    // Evaluate the pipeline with 16-bit values
    safe_copy(in16, data + offset, sizeof(cmsUInt16Number) * 3);
    offset += sizeof(cmsUInt16Number) * 3;
    cmsPipelineEval16(in16, out16, pipeline);

    // Smooth the tone curve
    lambda = *reinterpret_cast<const cmsFloat64Number*>(data + offset);
    offset += sizeof(cmsFloat64Number);
    success = cmsSmoothToneCurve(toneCurve, lambda);
    if (!success) {
        cmsPipelineFree(pipeline);
        cmsFreeToneCurve(toneCurve);
        return 0;
    }

    // Slice space with float values
    nInputs = safe_cast<cmsUInt32Number>(data[offset++], "cmsUInt32Number");
    if (nInputs >= cmsMAXCHANNELS) {
        cmsPipelineFree(pipeline);
        cmsFreeToneCurve(toneCurve);
        return 0;
    }
    for (cmsUInt32Number i = 0; i < nInputs; ++i) {
        clutPoints[i] = safe_cast<cmsUInt32Number>(data[offset++], "cmsUInt32Number");
    }
    cmsSliceSpaceFloat(nInputs, clutPoints, nullptr, nullptr);

    // Slice space with 16-bit values
    cmsSliceSpace16(nInputs, clutPoints, nullptr, nullptr);

    // Free resources
    cmsPipelineFree(pipeline);
    cmsFreeToneCurve(toneCurve);

    return 0;
}
