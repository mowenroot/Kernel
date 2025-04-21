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
    return (char**)calloc(count, sizeof(char*));
}

// Function to safely free an array of strings
void safe_free_string_array(char** array, size_t count) {
    if (!array) return;
    for (size_t i = 0; i < count; ++i) {
        free(array[i]);
    }
    free(array);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 1) return 0;

    // Initialize the IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    if (!hIT8) return 0;

    // Define the double format using a portion of the input data
    const char* formatter = (const char*)data;
    cmsIT8DefineDblFormat(hIT8, formatter);

    // Enumerate properties and handle potential errors
    char** propertyNames = nullptr;
    cmsUInt32Number propertyCount = cmsIT8EnumProperties(hIT8, &propertyNames);
    if (propertyCount > 0) {
        safe_free_string_array(propertyNames, propertyCount);
    }

    // Enumerate data format and handle potential errors
    char** sampleNames = nullptr;
    int sampleCount = cmsIT8EnumDataFormat(hIT8, &sampleNames);
    if (sampleCount > 0) {
        safe_free_string_array(sampleNames, sampleCount);
    }

    // Enumerate subproperties of a property derived from input data
    const char* propName = safe_strndup(data, size);
    const char** subpropertyNames = nullptr; // Changed from const char*** to const char**
    cmsUInt32Number subpropertyCount = cmsIT8EnumPropertyMulti(hIT8, propName, &subpropertyNames);
    if (subpropertyCount > 0) {
        free((void*)subpropertyNames);
    }
    free((void*)propName);

    // Free the IT8 handle and all associated resources
    cmsIT8Free(hIT8);

    return 0;
}
