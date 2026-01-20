#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzzer input
int extractInt(const uint8_t* data, size_t size, size_t& offset, size_t maxSize) {
    if (offset + sizeof(int) > size) {
        return 0; // Not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return value;
}

// Function to safely extract a pointer from the fuzzer input
void* extractPointer(const uint8_t* data, size_t size, size_t& offset, size_t maxSize) {
    if (offset + sizeof(void*) > size) {
        return nullptr; // Not enough data
    }
    void* ptr = *reinterpret_cast<void* const*>(data + offset);
    offset += sizeof(void*);
    return ptr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int) + sizeof(void*)) {
        return 0;
    }

    // Initialize variables
    size_t offset = 0;
    int colorSpaceInt = extractInt(data, size, offset, size);
    void* userData = extractPointer(data, size, offset, size);

    // Create a context
    cmsContext context = cmsCreateContext(nullptr, userData);
    if (!context) {
        return 0; // Failed to create context
    }

    // Get the user data from the context
    void* retrievedUserData = cmsGetContextUserData(context);
    if (retrievedUserData != userData) {
        cmsDeleteContext(context);
        return 0; // User data mismatch
    }

    // Convert the integer to a color space signature
    cmsColorSpaceSignature colorSpaceSignature = _cmsICCcolorSpace(colorSpaceInt);
    if (colorSpaceSignature == 0) {
        cmsDeleteContext(context);
        return 0; // Invalid color space
    }

    // Map the color space signature to a PT_ constant
    int ptConstant = _cmsLCMScolorSpace(colorSpaceSignature);
    if (ptConstant == 0) {
        cmsDeleteContext(context);
        return 0; // Invalid PT_ constant
    }

    // Clean up the context
    cmsDeleteContext(context);

    return 0;
}
