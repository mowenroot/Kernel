#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int32_t extractInt(const uint8_t* data, size_t size, size_t& offset, size_t intSize) {
    if (offset + intSize > size) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = 0;
    memcpy(&value, data + offset, intSize);
    offset += intSize;
    return value;
}

// Function to safely extract a string from the fuzz input
const char* extractString(const uint8_t* data, size_t size, size_t& offset, size_t maxLen) {
    if (offset + maxLen > size) {
        return nullptr; // Return nullptr if not enough data
    }
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += maxLen;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsContext context = nullptr;
    cmsHANDLE gbdHandle = nullptr;

    // Extract input values from fuzz data
    int32_t contextPluginSize = extractInt(data, size, offset, sizeof(int32_t));
    int32_t userDataSize = extractInt(data, size, offset, sizeof(int32_t));

    // Ensure sizes are within reasonable limits to prevent excessive memory usage
    if (contextPluginSize > 1024 || userDataSize > 1024) {
        return 0;
    }

    // Allocate memory for context plugin and user data
    void* contextPlugin = nullptr;
    void* userData = nullptr;

    if (contextPluginSize > 0) {
        contextPlugin = malloc(contextPluginSize);
        if (!contextPlugin) {
            return 0; // Allocation failed
        }
        memcpy(contextPlugin, data + offset, contextPluginSize);
        offset += contextPluginSize;
    }

    if (userDataSize > 0) {
        userData = malloc(userDataSize);
        if (!userData) {
            free(contextPlugin);
            return 0; // Allocation failed
        }
        memcpy(userData, data + offset, userDataSize);
        offset += userDataSize;
    }

    // Create a context
    context = cmsCreateContext(contextPlugin, userData);
    if (!context) {
        free(contextPlugin);
        free(userData);
        return 0; // Context creation failed
    }

    // Allocate a cmsGDB structure
    gbdHandle = cmsGBDAlloc(context);
    if (!gbdHandle) {
        cmsDeleteContext(context);
        free(contextPlugin);
        free(userData);
        return 0; // Allocation failed
    }

    // Free the cmsGDB structure
    cmsGBDFree(gbdHandle);

    // Delete the context
    cmsDeleteContext(context);

    // Free allocated memory
    free(contextPlugin);
    free(userData);

    return 0;
}
