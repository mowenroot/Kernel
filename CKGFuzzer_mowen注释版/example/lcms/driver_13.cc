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

// Function to safely convert a double from fuzz input
cmsFloat64Number safe_strtod(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return 0.0;
    cmsFloat64Number value = strtod(str, nullptr);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for at least one operation
    if (size < 1) return 0;

    // Create an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Pass NULL as the ContextID
    if (!hIT8) return 0;

    // Variables for API inputs
    char* key = nullptr;
    char* valueStr = nullptr;
    char* comment = nullptr;
    char* patchNameBuffer = nullptr;
    const char* retrievedValue = nullptr;
    cmsFloat64Number valueDbl = 0.0;

    // Allocate memory for patch name buffer
    patchNameBuffer = (char*)malloc(256); // Replace MAXSTR with a reasonable size
    if (!patchNameBuffer) {
        cmsIT8Free(hIT8);
        return 0;
    }

    // Set a string property
    key = safe_strndup(data, size / 2);
    valueStr = safe_strndup(data + size / 2, size - size / 2);
    if (key && valueStr) {
        cmsIT8SetPropertyStr(hIT8, key, valueStr);
    }

    // Set a comment
    comment = safe_strndup(data, size);
    if (comment) {
        cmsIT8SetComment(hIT8, comment);
    }

    // Get a property
    if (key) {
        retrievedValue = cmsIT8GetProperty(hIT8, key);
        if (retrievedValue) {
            // Use retrievedValue as needed
        }
    }

    // Get a double property
    if (key) {
        valueDbl = cmsIT8GetPropertyDbl(hIT8, key);
        // Use valueDbl as needed
    }

    // Set a double property
    if (key) {
        cmsIT8SetPropertyDbl(hIT8, key, valueDbl);
    }

    // Get patch name
    int patchIndex = static_cast<int>(data[0]) % 10; // Arbitrary index for fuzzing
    const char* patchName = cmsIT8GetPatchName(hIT8, patchIndex, patchNameBuffer);
    if (patchName) {
        // Use patchName as needed
    }

    // Free allocated resources
    free(key);
    free(valueStr);
    free(comment);
    free(patchNameBuffer);
    cmsIT8Free(hIT8);

    return 0;
}
