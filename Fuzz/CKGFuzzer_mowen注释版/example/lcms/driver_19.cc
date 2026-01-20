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
cmsFloat64Number safe_double_from_bytes(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) return 0.0;
    cmsFloat64Number val;
    memcpy(&val, data, sizeof(cmsFloat64Number));
    return val;
}

// Function to safely convert an integer from fuzz input
int safe_int_from_bytes(const uint8_t* data, size_t size) {
    if (size < sizeof(int)) return 0;
    int val;
    memcpy(&val, data, sizeof(int));
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 10) return 0;

    // Create an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Pass NULL as the ContextID
    if (!hIT8) return 0;

    // Extract strings and values from fuzz input
    char* comment = safe_strndup(data, size / 5);
    char* property = safe_strndup(data + size / 5, size / 5);
    char* patch = safe_strndup(data + 2 * (size / 5), size / 5);
    char* sample = safe_strndup(data + 3 * (size / 5), size / 5);
    char* sheetType = safe_strndup(data + 4 * (size / 5), size - 4 * (size / 5));

    cmsFloat64Number propertyValue = safe_double_from_bytes(data + size / 5, sizeof(cmsFloat64Number));
    cmsFloat64Number dataValue = safe_double_from_bytes(data + 2 * (size / 5), sizeof(cmsFloat64Number));
    int row = safe_int_from_bytes(data + 3 * (size / 5), sizeof(int));
    int col = safe_int_from_bytes(data + 4 * (size / 5), sizeof(int));

    // Set comment
    if (comment) {
        if (!cmsIT8SetComment(hIT8, comment)) {
            // Handle error
        }
        free(comment);
    }

    // Set property double
    if (property) {
        if (!cmsIT8SetPropertyDbl(hIT8, property, propertyValue)) {
            // Handle error
        }
        free(property);
    }

    // Set data double
    if (patch && sample) {
        if (!cmsIT8SetDataDbl(hIT8, patch, sample, dataValue)) {
            // Handle error
        }
        free(patch);
        free(sample);
    }

    // Set sheet type
    if (sheetType) {
        if (!cmsIT8SetSheetType(hIT8, sheetType)) {
            // Handle error
        }
        free(sheetType);
    }

    // Set data format
    if (sample) {
        if (!cmsIT8SetDataFormat(hIT8, 0, sample)) {
            // Handle error
        }
    }

    // Set data row col double
    if (!cmsIT8SetDataRowColDbl(hIT8, row, col, dataValue)) {
        // Handle error
    }

    // Free the IT8 handle
    cmsIT8Free(hIT8);

    return 0;
}
