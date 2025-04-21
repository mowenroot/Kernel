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

// Function to safely allocate memory for an array of strings
char** safe_alloc_string_array(size_t count) {
    return (char**)malloc(sizeof(char*) * count);
}

// Function to safely free an array of strings
void safe_free_string_array(char** array, size_t count) {
    if (array) {
        for (size_t i = 0; i < count; ++i) {
            free(array[i]);
        }
        free(array);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 1) return 0;

    // Create an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Pass NULL as the context for default context
    if (!hIT8) return 0;

    // Initialize variables for API calls
    char* sampleName = nullptr;
    char* propName = nullptr;
    char* dblFormat = nullptr;
    char** sampleNames = nullptr;
    char** propNames = nullptr;
    const char** subPropNames = nullptr;
    int sampleCount = 0;
    cmsUInt32Number propCount = 0;
    cmsUInt32Number subPropCount = 0;

    // Extract strings from fuzz input
    size_t sampleNameSize = data[0];
    size_t propNameSize = data[1];
    size_t dblFormatSize = data[2];

    if (size >= 3 + sampleNameSize + propNameSize + dblFormatSize) {
        sampleName = safe_strndup(data + 3, sampleNameSize);
        propName = safe_strndup(data + 3 + sampleNameSize, propNameSize);
        dblFormat = safe_strndup(data + 3 + sampleNameSize + propNameSize, dblFormatSize);
    }

    // Call cmsIT8FindDataFormat
    if (sampleName) {
        cmsIT8FindDataFormat(hIT8, sampleName);
    }

    // Call cmsIT8EnumPropertyMulti
    if (propName) {
        subPropCount = cmsIT8EnumPropertyMulti(hIT8, propName, &subPropNames);
        if (subPropNames) {
            // No need to free subPropNames as it's managed by the library
        }
    }

    // Call cmsIT8EnumDataFormat
    sampleCount = cmsIT8EnumDataFormat(hIT8, &sampleNames);
    if (sampleNames) {
        // No need to free sampleNames as it's managed by the library
    }

    // Call cmsIT8SetDataFormat
    if (sampleName && sampleCount > 0) {
        cmsIT8SetDataFormat(hIT8, sampleCount - 1, sampleName);
    }

    // Call cmsIT8EnumProperties
    propCount = cmsIT8EnumProperties(hIT8, &propNames);
    if (propNames) {
        // No need to free propNames as it's managed by the library
    }

    // Call cmsIT8DefineDblFormat
    if (dblFormat) {
        cmsIT8DefineDblFormat(hIT8, dblFormat);
    }

    // Free allocated memory
    free(sampleName);
    free(propName);
    free(dblFormat);

    // Free the IT8 handle
    cmsIT8Free(hIT8);

    return 0;
}
