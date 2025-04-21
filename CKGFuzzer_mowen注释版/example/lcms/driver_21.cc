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
bool safe_double_from_bytes(const uint8_t* data, size_t size, cmsFloat64Number* val) {
    if (size < sizeof(cmsFloat64Number)) return false;
    memcpy(val, data, sizeof(cmsFloat64Number));
    return true;
}

// Function to safely convert an integer from fuzz input
bool safe_int_from_bytes(const uint8_t* data, size_t size, int* val) {
    if (size < sizeof(int)) return false;
    memcpy(val, data, sizeof(int));
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsFloat64Number) + sizeof(int) + 2 * (sizeof(char) + 1)) return 0;

    // Initialize IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Fixed: Added NULL as the ContextID argument
    if (!hIT8) return 0;

    // Extract and set comment
    char* comment = safe_strndup(data, size / 4);
    if (comment) {
        cmsIT8SetComment(hIT8, comment);
        free(comment);
    }

    // Extract and set property double
    cmsFloat64Number property_dbl;
    if (safe_double_from_bytes(data + size / 4, size / 4, &property_dbl)) {
        char* prop_name = safe_strndup(data + size / 2, size / 4);
        if (prop_name) {
            cmsIT8SetPropertyDbl(hIT8, prop_name, property_dbl);
            free(prop_name);
        }
    }

    // Extract and set data double
    cmsFloat64Number data_dbl;
    if (safe_double_from_bytes(data + size / 2, size / 4, &data_dbl)) {
        char* patch_name = safe_strndup(data + 3 * size / 4, size / 8);
        char* sample_name = safe_strndup(data + 7 * size / 8, size / 8);
        if (patch_name && sample_name) {
            cmsIT8SetDataDbl(hIT8, patch_name, sample_name, data_dbl);
            free(patch_name);
            free(sample_name);
        }
    }

    // Extract and set sheet type
    char* sheet_type = safe_strndup(data + 3 * size / 4, size / 4);
    if (sheet_type) {
        cmsIT8SetSheetType(hIT8, sheet_type);
        free(sheet_type);
    }

    // Extract and set data format
    int format_index;
    if (safe_int_from_bytes(data + 7 * size / 8, sizeof(int), &format_index)) {
        char* format_name = safe_strndup(data + 7 * size / 8 + sizeof(int), size / 8);
        if (format_name) {
            cmsIT8SetDataFormat(hIT8, format_index, format_name);
            free(format_name);
        }
    }

    // Extract and set data row col double
    cmsFloat64Number row_col_dbl;
    int row, col;
    if (safe_double_from_bytes(data + 7 * size / 8 + sizeof(int) + size / 8, size / 4, &row_col_dbl) &&
        safe_int_from_bytes(data + 7 * size / 8 + sizeof(int) + size / 8 + size / 4, sizeof(int), &row) &&
        safe_int_from_bytes(data + 7 * size / 8 + sizeof(int) + size / 8 + size / 4 + sizeof(int), sizeof(int), &col)) {
        cmsIT8SetDataRowColDbl(hIT8, row, col, row_col_dbl);
    }

    // Free the IT8 handle
    cmsIT8Free(hIT8);

    return 0;
}
