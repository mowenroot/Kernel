#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <algorithm> // Include for std::min

// Function to safely allocate memory and handle errors
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data with bounds checking
void safeCopy(void* dest, const void* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(cmsUInt32Number) * 4) {
        return 0;
    }

    // Extract parameters from the fuzz input
    cmsUInt32Number InputFormat = *reinterpret_cast<const cmsUInt32Number*>(data);
    cmsUInt32Number OutputFormat = *reinterpret_cast<const cmsUInt32Number*>(data + sizeof(cmsUInt32Number));
    cmsUInt32Number Intent = *reinterpret_cast<const cmsUInt32Number*>(data + 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number dwFlags = *reinterpret_cast<const cmsUInt32Number*>(data + 3 * sizeof(cmsUInt32Number));

    // Create profiles for the transform
    cmsHPROFILE InputProfile = cmsCreate_sRGBProfile();
    cmsHPROFILE OutputProfile = cmsCreate_sRGBProfile();

    if (!InputProfile || !OutputProfile) {
        cmsCloseProfile(InputProfile); // Corrected from cmsDeleteProfile to cmsCloseProfile
        cmsCloseProfile(OutputProfile); // Corrected from cmsDeleteProfile to cmsCloseProfile
        return 0;
    }

    // Create the transform
    cmsHTRANSFORM hTransform = cmsCreateTransform(InputProfile, InputFormat, OutputProfile, OutputFormat, Intent, dwFlags);
    if (!hTransform) {
        cmsCloseProfile(InputProfile); // Corrected from cmsDeleteProfile to cmsCloseProfile
        cmsCloseProfile(OutputProfile); // Corrected from cmsDeleteProfile to cmsCloseProfile
        return 0;
    }

    // Get the input format of the transform
    cmsUInt32Number retrievedInputFormat = cmsGetTransformInputFormat(hTransform);

    // Allocate buffers for transform operations
    size_t bufferSize = 1024; // Example size, adjust as needed
    std::unique_ptr<uint8_t[]> inputBuffer(new uint8_t[bufferSize]);
    std::unique_ptr<uint8_t[]> outputBuffer(new uint8_t[bufferSize]);

    // Fill input buffer with fuzz data
    size_t copySize = std::min(bufferSize, size - 4 * sizeof(cmsUInt32Number)); // Corrected from std::min to std::min
    safeCopy(inputBuffer.get(), data + 4 * sizeof(cmsUInt32Number), copySize);

    // Perform the transform using cmsDoTransform
    cmsDoTransform(hTransform, inputBuffer.get(), outputBuffer.get(), bufferSize);

    // Perform the transform using cmsDoTransformLineStride
    cmsDoTransformLineStride(hTransform, inputBuffer.get(), outputBuffer.get(), 1, 1, bufferSize, bufferSize, 0, 0);

    // Clean up resources
    cmsDeleteTransform(hTransform);
    cmsCloseProfile(InputProfile); // Corrected from cmsDeleteProfile to cmsCloseProfile
    cmsCloseProfile(OutputProfile); // Corrected from cmsDeleteProfile to cmsCloseProfile

    return 0;
}
