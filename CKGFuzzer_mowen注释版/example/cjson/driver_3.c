#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely get a boolean value from fuzz input
cJSON_bool get_boolean_from_input(const uint8_t *data, size_t size) {
    if (size == 0) return cJSON_False;
    return (data[0] % 2 == 0) ? cJSON_True : cJSON_False;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

    // Initialize variables
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *string_item = NULL;
    cJSON *bool_item = NULL;
    cJSON *null_item = NULL;
    char *name = NULL;
    char *string_value = NULL;

    // Create a JSON object
    root = cJSON_CreateObject();
    if (!root) goto cleanup;

    // Create a JSON array
    array = cJSON_CreateArray();
    if (!array) goto cleanup;

    // Create a JSON string item
    string_value = safe_strndup(data, size / 2);
    if (!string_value) goto cleanup;
    string_item = cJSON_CreateString(string_value);
    if (!string_item) goto cleanup;

    // Create a JSON boolean item
    bool_item = cJSON_CreateBool(get_boolean_from_input(data, size));
    if (!bool_item) goto cleanup;

    // Create a JSON null item
    null_item = cJSON_CreateNull();
    if (!null_item) goto cleanup;

    // Add the null item to the root object
    name = safe_strndup(data + (size / 2), size / 2);
    if (!name) goto cleanup;
    if (!cJSON_AddNullToObject(root, name)) goto cleanup;

    // Add items to the array
    if (!cJSON_AddItemToArray(array, string_item)) goto cleanup;
    if (!cJSON_AddItemToArray(array, bool_item)) goto cleanup;
    if (!cJSON_AddItemToArray(array, null_item)) goto cleanup;

    // Add the array to the root object
    if (!cJSON_AddItemToObject(root, "array", array)) goto cleanup;

    // Successfully created and populated the JSON structure
    // No need to return anything as the fuzzer will continue

cleanup:
    // Free allocated memory
    if (root) cJSON_Delete(root);
    if (name) free(name);
    if (string_value) free(string_value);

    return 0;
}
