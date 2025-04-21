#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int32_t SafeExtractInt(const uint8_t* data, size_t size, size_t& offset, size_t max_bytes = 4) {
    if (offset + max_bytes > size) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = 0;
    memcpy(&value, data + offset, max_bytes);
    offset += max_bytes;
    return value;
}

// Function to safely extract a double from the fuzz input
double SafeExtractDouble(const uint8_t* data, size_t size, size_t& offset, size_t max_bytes = 8) {
    if (offset + max_bytes > size) {
        return 0.0; // Return a default value if not enough data
    }
    double value = 0.0;
    memcpy(&value, data + offset, max_bytes);
    offset += max_bytes;
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = nullptr;
    cmsUInt32Number model = 0;
    cmsUInt32Number renderingIntent = 0;
    cmsUInt32Number supportedIntents[10];
    char* intentDescriptions[10];
    cmsUInt32Number intentCount = 0;

    // Create a new profile
    hProfile = cmsCreateProfilePlaceholder(nullptr);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Extract data from fuzz input
    model = SafeExtractInt(data, size, offset);
    renderingIntent = SafeExtractInt(data, size, offset);

    // Set profile header model
    cmsSetHeaderModel(hProfile, model);

    // Set profile rendering intent
    cmsSetHeaderRenderingIntent(hProfile, renderingIntent);

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Detect Total Area Coverage (TAC)
    cmsFloat64Number tac = cmsDetectTAC(hProfile);

    // Get supported intents
    intentCount = cmsGetSupportedIntents(10, supportedIntents, intentDescriptions);

    // Clean up
    cmsCloseProfile(hProfile);
    hProfile = nullptr;

    // Free intent descriptions
    for (cmsUInt32Number i = 0; i < intentCount; ++i) {
        free(intentDescriptions[i]);
    }

    return 0;
}
