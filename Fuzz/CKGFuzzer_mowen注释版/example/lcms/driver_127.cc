#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* SafeStrndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert a double from fuzz input
bool SafeDouble(const uint8_t* data, size_t size, double* val) {
    if (size == 0) return false;
    char* str = SafeStrndup(data, size);
    if (!str) return false;
    char* endptr;
    *val = strtod(str, &endptr);
    free(str);
    return (endptr != str && *endptr == '\0');
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    cmsHANDLE hIT8 = nullptr;
    cmsUInt32Number bytesNeeded = 0;
    char* propName = nullptr;
    char* sampleName = nullptr;
    char* patchName = nullptr;
    double propValue = 0.0;
    double dataValue = 0.0;
    char* dataFormat = nullptr;
    char* dataStr = nullptr;

    // Allocate memory for IT8 object
    hIT8 = cmsIT8LoadFromMem(nullptr, data, size);
    if (!hIT8) return 0;

    // Set property double
    propName = SafeStrndup(data, 8);
    if (propName && SafeDouble(data + 8, 8, &propValue)) {
        cmsIT8SetPropertyDbl(hIT8, propName, propValue);
    }
    free(propName);

    // Set data double
    sampleName = SafeStrndup(data + 16, 8);
    patchName = SafeStrndup(data + 24, 8);
    if (sampleName && patchName && SafeDouble(data + 32, 8, &dataValue)) {
        cmsIT8SetDataDbl(hIT8, patchName, sampleName, dataValue);
    }
    free(sampleName);
    free(patchName);

    // Set data format
    dataFormat = SafeStrndup(data + 40, 8);
    if (dataFormat) {
        cmsIT8SetDataFormat(hIT8, 0, dataFormat);
    }
    free(dataFormat);

    // Set data
    sampleName = SafeStrndup(data + 48, 8);
    patchName = SafeStrndup(data + 56, 8);
    dataStr = SafeStrndup(data + 64, size - 64);
    if (sampleName && patchName && dataStr) {
        cmsIT8SetData(hIT8, patchName, sampleName, dataStr);
    }
    free(sampleName);
    free(patchName);
    free(dataStr);

    // Save IT8 object to memory
    cmsIT8SaveToMem(hIT8, nullptr, &bytesNeeded);

    // Free the IT8 object
    cmsIT8Free(hIT8);

    return 0;
}
