#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate memory and copy data from fuzz input
void* safe_alloc_and_copy(const uint8_t* data, size_t size) {
    void* ptr = malloc(size);
    if (ptr) {
        safe_copy(ptr, data, size);
    }
    return ptr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(void*) * 2) {
        return 0;
    }

    // Extract user data and plugin data from the fuzz input
    void* userData = safe_alloc_and_copy(data, sizeof(void*));
    void* pluginData = safe_alloc_and_copy(data + sizeof(void*), sizeof(void*));

    // Create a new context with the extracted user data and plugin data
    cmsContext context = cmsCreateContext(pluginData, userData);
    if (!context) {
        free(userData);
        free(pluginData);
        return 0;
    }

    // Register plugins using the context
    if (!cmsPluginTHR(context, pluginData)) {
        cmsDeleteContext(context);
        free(userData);
        free(pluginData);
        return 0;
    }

    // Retrieve and verify the user data from the context
    void* retrievedUserData = cmsGetContextUserData(context);
    if (retrievedUserData != userData) {
        cmsDeleteContext(context);
        free(userData);
        free(pluginData);
        return 0;
    }

    // Duplicate the context with new user data (if available)
    void* newUserData = safe_alloc_and_copy(data + sizeof(void*) * 2, sizeof(void*));
    cmsContext duplicatedContext = cmsDupContext(context, newUserData);
    if (!duplicatedContext) {
        cmsDeleteContext(context);
        free(userData);
        free(pluginData);
        free(newUserData);
        return 0;
    }

    // Clean up resources
    cmsDeleteContext(duplicatedContext);
    cmsDeleteContext(context);
    free(userData);
    free(pluginData);
    free(newUserData);

    return 0;
}
