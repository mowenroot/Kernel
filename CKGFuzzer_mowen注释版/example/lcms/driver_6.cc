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

// Function to safely convert fuzz input to an integer
int safe_atoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Create an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Fixed: Added NULL as the ContextID argument
    if (!hIT8) return 0;

    // Extract strings and integers from fuzz input
    char* sampleName = safe_strndup(data, size / 4);
    char* patchName = safe_strndup(data + size / 4, size / 4);
    char* dataValue = safe_strndup(data + size / 2, size / 4);
    int row = safe_atoi(data + 3 * size / 4, size / 4);
    int col = safe_atoi(data + 3 * size / 4 + size / 8, size / 8);

    // Ensure all strings are valid
    if (!sampleName || !patchName || !dataValue) {
        cmsIT8Free(hIT8);
        free(sampleName);
        free(patchName);
        free(dataValue);
        return 0;
    }

    // Test cmsIT8FindDataFormat
    int formatIndex = cmsIT8FindDataFormat(hIT8, sampleName);
    if (formatIndex < 0) {
        // Handle error
    }

    // Test cmsIT8GetDataRowCol
    const char* rowColData = cmsIT8GetDataRowCol(hIT8, row, col);
    if (!rowColData) {
        // Handle error
    }

    // Test cmsIT8EnumDataFormat
    char** sampleNames = nullptr;
    int numSamples = cmsIT8EnumDataFormat(hIT8, &sampleNames);
    if (numSamples < 0) {
        // Handle error
    }

    // Test cmsIT8SetDataFormat
    cmsBool setDataFormatResult = cmsIT8SetDataFormat(hIT8, formatIndex, sampleName);
    if (!setDataFormatResult) {
        // Handle error
    }

    // Test cmsIT8GetData
    const char* getDataResult = cmsIT8GetData(hIT8, patchName, sampleName);
    if (!getDataResult) {
        // Handle error
    }

    // Test cmsIT8SetData
    cmsBool setDataResult = cmsIT8SetData(hIT8, patchName, sampleName, dataValue);
    if (!setDataResult) {
        // Handle error
    }

    // Free allocated resources
    cmsIT8Free(hIT8);
    free(sampleName);
    free(patchName);
    free(dataValue);
    if (sampleNames) {
        for (int i = 0; i < numSamples; ++i) {
            free(sampleNames[i]);
        }
        free(sampleNames);
    }

    return 0;
}
