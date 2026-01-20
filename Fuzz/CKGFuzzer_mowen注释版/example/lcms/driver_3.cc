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

// Function to safely allocate memory for an array of strings
char** safe_alloc_string_array(size_t count) {
    return (char**)malloc(sizeof(char*) * count);
}

// Function to safely free an array of strings
void safe_free_string_array(char** array, size_t count) {
    if (array) {
        for (size_t i = 0; i < count; ++i) {
            free(array[i]);
        }
        free(array);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

    // Create an IT8 handle
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Fixed: Added NULL as the ContextID argument
    if (!hIT8) return 0;

    // Safely extract strings from fuzz input
    const size_t max_str_len = 64; // Arbitrary limit to prevent excessive memory usage
    char* sample_name = safe_strndup(data, size, max_str_len);
    char* prop_name = safe_strndup(data + max_str_len, size - max_str_len, max_str_len);
    char* dbl_format = safe_strndup(data + 2 * max_str_len, size - 2 * max_str_len, max_str_len);

    // Initialize variables for API calls
    int result;
    const char** subprop_names = nullptr;
    char** sample_names = nullptr;
    char** prop_names = nullptr;
    cmsUInt32Number count;

    // Call cmsIT8FindDataFormat
    if (sample_name) {
        result = cmsIT8FindDataFormat(hIT8, sample_name);
        if (result < 0) {
            // Handle error
        }
    }

    // Call cmsIT8EnumPropertyMulti
    if (prop_name) {
        count = cmsIT8EnumPropertyMulti(hIT8, prop_name, &subprop_names);
        if (count > 0) {
            // Safely free the subproperty names array
            free(subprop_names);
        }
    }

    // Call cmsIT8EnumDataFormat
    result = cmsIT8EnumDataFormat(hIT8, &sample_names);
    if (result > 0) {
        // Safely free the sample names array
        safe_free_string_array(sample_names, result);
    }

    // Call cmsIT8SetDataFormat
    if (sample_name) {
        cmsBool success = cmsIT8SetDataFormat(hIT8, 0, sample_name);
        if (!success) {
            // Handle error
        }
    }

    // Call cmsIT8EnumProperties
    count = cmsIT8EnumProperties(hIT8, &prop_names);
    if (count > 0) {
        // Safely free the property names array
        safe_free_string_array(prop_names, count);
    }

    // Call cmsIT8DefineDblFormat
    if (dbl_format) {
        cmsIT8DefineDblFormat(hIT8, dbl_format);
    }

    // Free allocated memory
    free(sample_name);
    free(prop_name);
    free(dbl_format);

    // Free the IT8 handle
    cmsIT8Free(hIT8);

    return 0;
}
