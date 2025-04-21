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

// Function to safely convert fuzz input to a double
double SafeStrtod(const uint8_t* data, size_t size) {
    char* str = SafeStrndup(data, size);
    if (!str) return 0.0;
    char* endptr;
    double value = strtod(str, &endptr);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHANDLE hIT8 = nullptr;
    char* sampleName = nullptr;
    char** propertyNames = nullptr;
    char** sampleNames = nullptr;
    const char** subpropertyNames = nullptr;
    int result = 0;

    // Allocate and initialize the cmsIT8 structure
    hIT8 = cmsIT8Alloc(nullptr);
    if (!hIT8) return 0;

    // Define the double format using a portion of the fuzz input
    cmsIT8DefineDblFormat(hIT8, (const char*)data);

    // Enumerate properties and handle potential errors
    cmsUInt32Number numProperties = cmsIT8EnumProperties(hIT8, &propertyNames);
    if (numProperties == 0 || !propertyNames) {
        cmsIT8Free(hIT8);
        return 0;
    }

    // Enumerate data formats and handle potential errors
    int numSamples = cmsIT8EnumDataFormat(hIT8, &sampleNames);
    if (numSamples == 0 || !sampleNames) {
        for (cmsUInt32Number i = 0; i < numProperties; ++i) free(propertyNames[i]);
        free(propertyNames);
        cmsIT8Free(hIT8);
        return 0;
    }

    // Find a data format using a portion of the fuzz input
    sampleName = SafeStrndup(data + 8, size - 8);
    if (sampleName) {
        result = cmsIT8FindDataFormat(hIT8, sampleName);
        free(sampleName);
    }

    // Enumerate subproperties for the first property and handle potential errors
    cmsUInt32Number numSubproperties = cmsIT8EnumPropertyMulti(hIT8, propertyNames[0], &subpropertyNames);
    if (numSubproperties > 0 && subpropertyNames) {
        for (cmsUInt32Number i = 0; i < numSubproperties; ++i) free((void*)subpropertyNames[i]);
        free(subpropertyNames);
    }

    // Free allocated resources
    for (cmsUInt32Number i = 0; i < numProperties; ++i) free(propertyNames[i]);
    free(propertyNames);
    for (int i = 0; i < numSamples; ++i) free(sampleNames[i]);
    free(sampleNames);
    cmsIT8Free(hIT8);

    return 0;
}
