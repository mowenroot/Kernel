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

// Function to safely convert fuzz input to a double
cmsFloat64Number safe_atod(const uint8_t* data, size_t size) {
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

    // Initialize variables
    cmsHANDLE hIT8 = nullptr;
    const char* result = nullptr;
    cmsBool success = FALSE;

    // Load IT8 data from memory
    hIT8 = cmsIT8LoadFromMem(nullptr, data, size);
    if (!hIT8) return 0;

    // Set data format
    const char* format = safe_strndup(data, size % 16);
    if (format) {
        success = cmsIT8SetDataFormat(hIT8, 0, format);
        free((void*)format);
        if (!success) goto cleanup;
    }

    // Set property double
    cmsFloat64Number prop_val; // Move declaration here to avoid jump bypass
    prop_val = safe_atod(data, size % 8);
    success = cmsIT8SetPropertyDbl(hIT8, "Property", prop_val);
    if (!success) goto cleanup;

    // Set data row col double
    cmsFloat64Number row_col_val; // Move declaration here to avoid jump bypass
    row_col_val = safe_atod(data + 8, size % 8);
    success = cmsIT8SetDataRowColDbl(hIT8, 1, 1, row_col_val);
    if (!success) goto cleanup;

    // Get data row col
    result = cmsIT8GetDataRowCol(hIT8, 1, 1);
    if (!result) goto cleanup;

cleanup:
    // Free resources
    if (hIT8) cmsIT8Free(hIT8);

    return 0;
}
