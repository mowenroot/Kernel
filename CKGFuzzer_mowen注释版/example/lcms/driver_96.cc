#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int32_t extractInt(const uint8_t* data, size_t size, size_t& offset, size_t maxSize) {
    if (offset + sizeof(int32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = *reinterpret_cast<const int32_t*>(data + offset);
    offset += sizeof(int32_t);
    return value;
}

// Function to safely extract a pointer from the fuzz input
void* extractPointer(const uint8_t* data, size_t size, size_t& offset, size_t maxSize) {
    if (offset + sizeof(void*) > size) {
        return nullptr; // Return nullptr if not enough data
    }
    void* ptr = *reinterpret_cast<void* const*>(data + offset);
    offset += sizeof(void*);
    return ptr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = nullptr;
    cmsContext context = nullptr;
    cmsCIEXYZ blackPoint;
    cmsUInt32Number intents[10];
    char* descriptions[10];
    cmsUInt32Number intentCount = 0;

    // Extract inputs from fuzz data
    int32_t intent = extractInt(data, size, offset, size);
    int32_t usedDirection = extractInt(data, size, offset, size);
    void* newUserData = extractPointer(data, size, offset, size);

    // Create a new context
    context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0; // Failed to create context
    }

    // Create a new profile
    hProfile = cmsCreateProfilePlaceholder(context);
    if (!hProfile) {
        cmsDeleteContext(context);
        return 0; // Failed to create profile
    }

    // Call cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(hProfile, intent, usedDirection);

    // Call cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Call cmsDetectDestinationBlackPoint
    cmsBool detectedBlackPoint = cmsDetectDestinationBlackPoint(&blackPoint, hProfile, intent, 0);

    // Call cmsGetSupportedIntents
    intentCount = cmsGetSupportedIntents(10, intents, descriptions);

    // Call cmsDupContext
    cmsContext dupContext = cmsDupContext(context, newUserData);
    if (dupContext) {
        cmsDeleteContext(dupContext);
    }

    // Clean up
    cmsCloseProfile(hProfile);
    cmsDeleteContext(context);

    // Free descriptions if allocated
    for (cmsUInt32Number i = 0; i < intentCount; ++i) {
        if (descriptions[i]) {
            free(descriptions[i]);
        }
    }

    return 0;
}
