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

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsFloat64Number) + 2 * sizeof(char)) return 0;

    // Create an IT8 container
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Fixed: Added NULL as the ContextID argument
    if (!hIT8) return 0;

    // Variables for API inputs
    char* key = nullptr;
    char* val = nullptr;
    char* sheetType = nullptr;
    char* sample = nullptr;
    cmsFloat64Number dblVal;

    // Allocate memory for strings derived from fuzz input
    key = safe_strndup(data, size / 4);
    val = safe_strndup(data + size / 4, size / 4);
    sheetType = safe_strndup(data + size / 2, size / 4);
    sample = safe_strndup(data + 3 * size / 4, size / 4);

    // Convert a portion of the input to a double
    if (!safe_double_from_bytes(data + size - sizeof(cmsFloat64Number), sizeof(cmsFloat64Number), &dblVal)) {
        cmsIT8Free(hIT8);
        free(key);
        free(val);
        free(sheetType);
        free(sample);
        return 0;
    }

    // Call each API function with appropriate error handling
    if (key && val) {
        if (!cmsIT8SetPropertyStr(hIT8, key, val)) {
            // Handle error
        }
    }

    if (key) {
        if (!cmsIT8SetPropertyDbl(hIT8, key, dblVal)) {
            // Handle error
        }
    }

    if (key && sample) {
        if (!cmsIT8SetDataDbl(hIT8, key, sample, dblVal)) {
            // Handle error
        }
    }

    if (sheetType) {
        if (!cmsIT8SetSheetType(hIT8, sheetType)) {
            // Handle error
        }
    }

    if (key && val) {
        if (!cmsIT8SetPropertyUncooked(hIT8, key, val)) {
            // Handle error
        }
    }

    if (sample) {
        if (!cmsIT8SetDataFormat(hIT8, 0, sample)) {
            // Handle error
        }
    }

    // Free allocated resources
    cmsIT8Free(hIT8);
    free(key);
    free(val);
    free(sheetType);
    free(sample);

    return 0;
}
