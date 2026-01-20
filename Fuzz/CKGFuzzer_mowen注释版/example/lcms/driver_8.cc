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

    // Create an IT8 handle with a valid cmsContext
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL); // Passing NULL as the context is common for default context
    if (!hIT8) return 0;

    // Variables for API calls
    char* sample_name = nullptr;
    char** property_names = nullptr;
    char** sample_names = nullptr;
    char* patch_name = nullptr;
    char* data_format = nullptr;
    char* data_value = nullptr;
    int result;

    // Safely extract strings from fuzz input
    sample_name = safe_strndup(data, size, 255);
    patch_name = safe_strndup(data + 256, size - 256, 255);
    data_format = safe_strndup(data + 512, size - 512, 255);
    data_value = safe_strndup(data + 768, size - 768, 255);

    // Call cmsIT8FindDataFormat
    if (sample_name) {
        result = cmsIT8FindDataFormat(hIT8, sample_name);
        if (result < 0) {
            // Handle error
        }
    }

    // Call cmsIT8EnumProperties
    cmsUInt32Number property_count = cmsIT8EnumProperties(hIT8, &property_names);
    if (property_count > 0) {
        // Safely free the property names array
        safe_free_string_array(property_names, property_count);
    }

    // Call cmsIT8EnumDataFormat
    int sample_count = cmsIT8EnumDataFormat(hIT8, &sample_names);
    if (sample_count > 0) {
        // Safely free the sample names array
        safe_free_string_array(sample_names, sample_count);
    }

    // Call cmsIT8SetDataFormat
    if (data_format) {
        cmsBool success = cmsIT8SetDataFormat(hIT8, 0, data_format);
        if (!success) {
            // Handle error
        }
    }

    // Call cmsIT8GetData
    if (patch_name && sample_name) {
        const char* retrieved_data = cmsIT8GetData(hIT8, patch_name, sample_name);
        if (!retrieved_data) {
            // Handle error
        }
    }

    // Call cmsIT8SetData
    if (patch_name && sample_name && data_value) {
        cmsBool success = cmsIT8SetData(hIT8, patch_name, sample_name, data_value);
        if (!success) {
            // Handle error
        }
    }

    // Free allocated memory
    free(sample_name);
    free(patch_name);
    free(data_format);
    free(data_value);

    // Free the IT8 handle
    cmsIT8Free(hIT8);

    return 0;
}
