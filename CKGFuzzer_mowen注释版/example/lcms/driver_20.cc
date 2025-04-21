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
    cmsFloat64Number val = strtod(str, nullptr);
    free(str);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Create an IT8 handle with a context
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Fixed: Added NULL as the ContextID argument
    if (!hIT8) return 0;

    // Define the double format
    const char* dblFormat = "%f";
    cmsIT8DefineDblFormat(hIT8, dblFormat);

    // Extract strings and double from fuzz input
    size_t sampleNameSize = size / 4;
    size_t patchNameSize = size / 4;
    size_t dataFormatSize = size / 4;
    size_t doubleSize = size - (sampleNameSize + patchNameSize + dataFormatSize);

    char* sampleName = safe_strndup(data, sampleNameSize);
    char* patchName = safe_strndup(data + sampleNameSize, patchNameSize);
    char* dataFormat = safe_strndup(data + sampleNameSize + patchNameSize, dataFormatSize);
    cmsFloat64Number value = safe_strtod(data + sampleNameSize + patchNameSize + dataFormatSize, doubleSize);

    // Set data format
    if (dataFormat) {
        cmsIT8SetDataFormat(hIT8, 0, dataFormat);
        free(dataFormat);
    }

    // Set data double
    if (sampleName && patchName) {
        cmsIT8SetDataDbl(hIT8, patchName, sampleName, value);
        free(sampleName);
        free(patchName);
    }

    // Enumerate data formats
    char** sampleNames = nullptr;
    int numSamples = cmsIT8EnumDataFormat(hIT8, &sampleNames);
    if (numSamples > 0) {
        for (int i = 0; i < numSamples; ++i) {
            free(sampleNames[i]);
        }
        free(sampleNames);
    }

    // Free the IT8 handle
    cmsIT8Free(hIT8);

    return 0;
}
