#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h> // Include stdbool.h for bool type

// Function to safely copy a string from fuzz input
static char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a cJSON object from fuzz input
static cJSON* safe_cJSON_ParseWithLengthOpts(const uint8_t *data, size_t size) {
    const char *parse_end = NULL;
    return cJSON_ParseWithLengthOpts((const char*)data, size, &parse_end, false);
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Initialize variables
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *item = NULL;
    char *json_str = NULL;
    int prebuffer = 1024; // Arbitrary buffer size for printing

    // Parse the input data into a cJSON object
    root = safe_cJSON_ParseWithLengthOpts(data, size);
    if (!root) goto cleanup;

    // Create an array reference
    array = cJSON_CreateArrayReference(root);
    if (!array) goto cleanup;

    // Add the array reference to the root object
    if (!cJSON_AddItemToObject(root, "array_ref", array)) {
        cJSON_Delete(array);
        goto cleanup;
    }

    // Delete an item from the array (if it exists)
    cJSON_DeleteItemFromArray(root, 0);

    // Print the JSON object to a buffer
    json_str = cJSON_PrintBuffered(root, prebuffer, true);
    if (!json_str) goto cleanup;

    // Clean up allocated resources
    free(json_str);

cleanup:
    if (root) cJSON_Delete(root);
    return 0;
}
