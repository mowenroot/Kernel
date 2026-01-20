#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* SafeStrndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a string from fuzz input with a maximum length
char* SafeStrndupMax(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = (size < max_len) ? size : max_len;
    return SafeStrndup(data, len);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 1) return 0;

    // Create an IT8 handle with a valid cmsContext
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Passing NULL as the context is common for default context
    if (!hIT8) return 0;

    // Safely create strings from fuzz input
    char* key = SafeStrndupMax(data, size, 256);
    char* val = SafeStrndupMax(data + 256, size - 256, 256);
    char* sample = SafeStrndupMax(data + 512, size - 512, 256);

    // Set a string property
    if (key && val) {
        cmsIT8SetPropertyStr(hIT8, key, val);
    }

    // Find data format
    if (sample) {
        cmsIT8FindDataFormat(hIT8, sample);
    }

    // Enumerate multi-properties
    const char** subpropertyNames = nullptr;
    cmsUInt32Number subpropertyCount = cmsIT8EnumPropertyMulti(hIT8, key, &subpropertyNames);
    if (subpropertyNames) {
        cmsIT8Free(subpropertyNames);
    }

    // Set uncooked property
    if (key && val) {
        cmsIT8SetPropertyUncooked(hIT8, key, val);
    }

    // Enumerate data formats
    char** sampleNames = nullptr;
    int sampleCount = cmsIT8EnumDataFormat(hIT8, &sampleNames);
    if (sampleNames) {
        cmsIT8Free(sampleNames);
    }

    // Set data format
    if (sample) {
        cmsIT8SetDataFormat(hIT8, 0, sample);
    }

    // Free allocated memory
    free(key);
    free(val);
    free(sample);

    // Free the IT8 handle
    cmsIT8Free(hIT8);

    return 0;
}
