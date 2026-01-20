#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
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

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for processing
    if (size < sizeof(cmsCIEXYZ) + sizeof(cmsJCh) + sizeof(cmsViewingConditions)) {
        return 0;
    }

    // Initialize variables
    cmsContext context = nullptr;
    cmsHANDLE model = nullptr;
    cmsCIEXYZ inputXYZ;
    cmsJCh inputJCh;
    cmsCIEXYZ outputXYZ;
    cmsViewingConditions viewingConditions;

    // Extract data from fuzzer input
    safeMemcpy(&inputXYZ, data, sizeof(cmsCIEXYZ));
    safeMemcpy(&inputJCh, data + sizeof(cmsCIEXYZ), sizeof(cmsJCh));
    safeMemcpy(&viewingConditions, data + sizeof(cmsCIEXYZ) + sizeof(cmsJCh), sizeof(cmsViewingConditions));

    // Create a context
    context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0;
    }

    // Initialize CIECAM02 model
    model = cmsCIECAM02Init(context, &viewingConditions);
    if (!model) {
        cmsDeleteContext(context);
        return 0;
    }

    // Perform forward transformation
    cmsCIECAM02Forward(model, &inputXYZ, &inputJCh);

    // Perform reverse transformation
    cmsCIECAM02Reverse(model, &inputJCh, &outputXYZ);

    // Clean up resources
    cmsCIECAM02Done(model);
    cmsDeleteContext(context);

    return 0;
}
