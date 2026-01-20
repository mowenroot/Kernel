#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory for a buffer
void* safe_malloc(size_t size) {
    if (size == 0) return nullptr;
    void* ptr = malloc(size);
    if (!ptr) abort(); // Handle allocation failure
    return ptr;
}

// Function to safely copy data into a buffer
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n == 0) return;
    if (!dest || !src) abort(); // Handle invalid pointers
    memcpy(dest, src, n);
}

// Function to safely free allocated memory
void safe_free(void* ptr) {
    if (ptr) free(ptr);
}

// Function to safely cast and access data
template<typename T>
T safe_cast(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(T) > size) abort(); // Handle out-of-bounds access
    T value = *reinterpret_cast<const T*>(data + offset);
    offset += sizeof(T);
    return value;
}

// Function to safely access a string
const char* safe_string(const uint8_t* data, size_t& offset, size_t size, size_t max_len) {
    if (offset + max_len > size) abort(); // Handle out-of-bounds access
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += max_len;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsUInt32Number) * 2) return 0;

    // Initialize variables
    size_t offset = 0;
    cmsPipeline* lut = cmsPipelineAlloc(0, 3, 3);
    if (!lut) return 0; // Handle allocation failure

    // Use RAII for automatic resource management
    std::unique_ptr<cmsPipeline, void(*)(cmsPipeline*)> lut_guard(lut, cmsPipelineFree);

    // Extract input values from fuzz data
    cmsUInt32Number stage_count = safe_cast<cmsUInt32Number>(data, offset, size);
    cmsUInt32Number eval_count = safe_cast<cmsUInt32Number>(data, offset, size);

    // Create and insert stages
    for (cmsUInt32Number i = 0; i < stage_count; ++i) {
        // Use cmsStageAllocIdentity with correct number of arguments
        cmsStage* stage = cmsStageAllocIdentity(0, 3); // Assuming 3 channels for identity stage
        if (!stage) break; // Handle allocation failure

        cmsStageLoc loc = (i % 2 == 0) ? cmsAT_BEGIN : cmsAT_END;
        if (!cmsPipelineInsertStage(lut, loc, stage)) {
            cmsStageFree(stage); // Free stage if insertion fails
            break;
        }
    }

    // Evaluate the pipeline
    for (cmsUInt32Number i = 0; i < eval_count; ++i) {
        // Ensure we have enough data for input and output buffers
        if (offset + sizeof(cmsFloat32Number) * 3 > size) break;

        // Allocate and initialize input/output buffers
        cmsFloat32Number* in = static_cast<cmsFloat32Number*>(safe_malloc(sizeof(cmsFloat32Number) * 3));
        cmsFloat32Number* out = static_cast<cmsFloat32Number*>(safe_malloc(sizeof(cmsFloat32Number) * 3));
        if (!in || !out) {
            safe_free(in);
            safe_free(out);
            break;
        }

        // Use RAII for automatic buffer cleanup
        std::unique_ptr<cmsFloat32Number, void(*)(void*)> in_guard(in, safe_free);
        std::unique_ptr<cmsFloat32Number, void(*)(void*)> out_guard(out, safe_free);

        // Copy input data from fuzz data
        safe_memcpy(in, data + offset, sizeof(cmsFloat32Number) * 3);
        offset += sizeof(cmsFloat32Number) * 3;

        // Evaluate the pipeline
        cmsPipelineEvalFloat(in, out, lut);

        // Optionally, evaluate in reverse
        if (offset + sizeof(cmsFloat32Number) * 3 <= size) {
            cmsFloat32Number* target = static_cast<cmsFloat32Number*>(safe_malloc(sizeof(cmsFloat32Number) * 3));
            cmsFloat32Number* result = static_cast<cmsFloat32Number*>(safe_malloc(sizeof(cmsFloat32Number) * 3));
            if (!target || !result) {
                safe_free(target);
                safe_free(result);
                break;
            }

            // Use RAII for automatic buffer cleanup
            std::unique_ptr<cmsFloat32Number, void(*)(void*)> target_guard(target, safe_free);
            std::unique_ptr<cmsFloat32Number, void(*)(void*)> result_guard(result, safe_free);

            // Copy target data from fuzz data
            safe_memcpy(target, data + offset, sizeof(cmsFloat32Number) * 3);
            offset += sizeof(cmsFloat32Number) * 3;

            // Evaluate in reverse
            cmsPipelineEvalReverseFloat(target, result, nullptr, lut);
        }
    }

    // Unlink stages
    cmsStage* unlinked_stage = nullptr;
    cmsPipelineUnlinkStage(lut, cmsAT_BEGIN, &unlinked_stage);
    if (unlinked_stage) cmsStageFree(unlinked_stage);

    // Count stages
    cmsUInt32Number count = cmsPipelineStageCount(lut);

    return 0;
}
