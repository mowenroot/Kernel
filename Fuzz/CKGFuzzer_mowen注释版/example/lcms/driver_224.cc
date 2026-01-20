#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for user data
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(void*) + 1) return 0;

    // Extract user data from fuzz input
    void* userData = safe_malloc(size);
    memcpy(userData, data, size);

    // Create a new context
    cmsContext context = cmsCreateContext(nullptr, userData);
    if (!context) {
        free(userData);
        return 0;
    }

    // Duplicate the context
    cmsContext dupContext = cmsDupContext(context, userData);
    if (!dupContext) {
        cmsDeleteContext(context);
        free(userData);
        return 0;
    }

    // Get the user data from the context
    void* retrievedUserData = cmsGetContextUserData(context);
    if (retrievedUserData != userData) {
        cmsDeleteContext(context);
        cmsDeleteContext(dupContext);
        free(userData);
        return 0;
    }

    // Delete the duplicated context
    cmsDeleteContext(dupContext);

    // Delete the original context
    cmsDeleteContext(context);

    // Free the user data
    free(userData);

    return 0;
}
