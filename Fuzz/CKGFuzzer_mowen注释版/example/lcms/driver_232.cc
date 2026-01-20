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

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsUInt32Number) * 4) {
        return 0;
    }

    // Extract necessary parameters from the fuzz input
    cmsUInt32Number inputFormat = *reinterpret_cast<const cmsUInt32Number*>(data);
    cmsUInt32Number outputFormat = *reinterpret_cast<const cmsUInt32Number*>(data + sizeof(cmsUInt32Number));
    cmsUInt32Number intent = *reinterpret_cast<const cmsUInt32Number*>(data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number flags = *reinterpret_cast<const cmsUInt32Number*>(data + 3 * sizeof(cmsUInt32Number));

    // Create profiles (dummy profiles for the sake of this example)
    cmsHPROFILE inputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE outputProfile = cmsCreate_sRGBProfile();

    if (!inputProfile || !outputProfile) {
        fprintf(stderr, "Failed to create profiles\n");
        return 0;
    }

    // Create the transform
    cmsHTRANSFORM transform = cmsCreateTransform(inputProfile, inputFormat, outputProfile, outputFormat, intent, flags);
    if (!transform) {
        fprintf(stderr, "Failed to create transform\n");
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    // Get the context ID and input/output formats for verification
    cmsContext contextID = cmsGetTransformContextID(transform);
    cmsUInt32Number retrievedInputFormat = cmsGetTransformInputFormat(transform);
    cmsUInt32Number retrievedOutputFormat = cmsGetTransformOutputFormat(transform);

    // Allocate buffers for transformation
    size_t bufferSize = size - 4 * sizeof(cmsUInt32Number);
    if (bufferSize == 0) {
        cmsDeleteTransform(transform);
        cmsCloseProfile(inputProfile);
        cmsCloseProfile(outputProfile);
        return 0;
    }

    void* inputBuffer = safeMalloc(bufferSize);
    void* outputBuffer = safeMalloc(bufferSize);

    // Copy the remaining data to the input buffer
    safeMemcpy(inputBuffer, data + 4 * sizeof(cmsUInt32Number), bufferSize);

    // Perform the transformation
    cmsDoTransform(transform, inputBuffer, outputBuffer, bufferSize);

    // Clean up
    free(inputBuffer);
    free(outputBuffer);
    cmsDeleteTransform(transform);
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

    return 0;
}
