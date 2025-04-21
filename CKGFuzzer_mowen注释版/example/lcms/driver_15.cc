#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = strnlen((const char*)data, size);
    if (len > max_len) len = max_len;
    char* str = (char*)malloc(len + 1);
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Function to safely convert fuzz input to a double
cmsFloat64Number safe_atof(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size, 255);
    if (!str) return 0.0;
    cmsFloat64Number val = strtod(str, NULL);
    free(str);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Create an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Fixed: Added NULL as the ContextID argument
    if (!hIT8) return 0;

    // Extract properties and data from fuzz input
    const char* prop_key = safe_strndup(data, size, 64);
    const char* prop_value = safe_strndup(data + 64, size - 64, 64);
    cmsFloat64Number prop_dbl = safe_atof(data + 128, size - 128);
    int row = (int)data[size - 4];
    int col = (int)data[size - 3];
    cmsFloat64Number data_dbl = safe_atof(data + size - 2, 2);

    // Set uncooked property
    if (prop_key && prop_value) {
        if (!cmsIT8SetPropertyUncooked(hIT8, prop_key, prop_value)) {
            // Handle error
        }
    }

    // Set double property
    if (prop_key) {
        if (!cmsIT8SetPropertyDbl(hIT8, prop_key, prop_dbl)) {
            // Handle error
        }
    }

    // Set data row and column
    if (!cmsIT8SetDataRowColDbl(hIT8, row, col, data_dbl)) {
        // Handle error
    }

    // Get double property
    cmsFloat64Number retrieved_prop_dbl = cmsIT8GetPropertyDbl(hIT8, prop_key);

    // Get data row and column
    cmsFloat64Number retrieved_data_dbl = cmsIT8GetDataRowColDbl(hIT8, row, col);

    // Clean up
    free((void*)prop_key);
    free((void*)prop_value);
    cmsIT8Free(hIT8);

    return 0;
}
