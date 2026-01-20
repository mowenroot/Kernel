#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a string from the fuzz input
const char* safe_extract_string(const uint8_t *data, size_t size, size_t *len) {
    if (size == 0) {
        *len = 0;
        return NULL;
    }
    *len = size - 1;
    return (const char*)data;
}

// Function to safely extract a number from the fuzz input
double safe_extract_number(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0.0;
    }
    // Convert the first byte to a double (for simplicity, this is a naive approach)
    return (double)*data;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Initialize variables
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *number = NULL;
    cJSON *string = NULL;
    cJSON *object = NULL;
    size_t str_len = 0;
    const char *str = NULL;
    double num = 0.0;

    // Create a root JSON object
    root = cJSON_CreateObject();
    if (root == NULL) {
        goto cleanup;
    }

    // Create a JSON array
    array = cJSON_CreateArray();
    if (array == NULL) {
        goto cleanup;
    }

    // Add the array to the root object
    if (cJSON_AddItemToObject(root, "array", array) == NULL) {
        goto cleanup;
    }

    // Extract a string from the fuzz input
    str = safe_extract_string(data, size, &str_len);
    if (str != NULL) {
        // Create a JSON string
        string = cJSON_CreateString(str);
        if (string == NULL) {
            goto cleanup;
        }

        // Add the string to the array
        if (cJSON_AddItemToArray(array, string) == NULL) {
            goto cleanup;
        }
    }

    // Extract a number from the fuzz input
    num = safe_extract_number(data, size);

    // Create a JSON number
    number = cJSON_CreateNumber(num);
    if (number == NULL) {
        goto cleanup;
    }

    // Add the number to the array
    if (cJSON_AddItemToArray(array, number) == NULL) {
        goto cleanup;
    }

    // Create a nested JSON object
    object = cJSON_CreateObject();
    if (object == NULL) {
        goto cleanup;
    }

    // Add the nested object to the root object
    if (cJSON_AddItemToObject(root, "nested_object", object) == NULL) {
        goto cleanup;
    }

    // Successfully constructed the JSON structure
    // No need to return anything, just clean up resources

cleanup:
    // Free all allocated resources
    if (root != NULL) {
        cJSON_Delete(root);
    }

    return 0;
}
