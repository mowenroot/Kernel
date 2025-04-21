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
    char *key = NULL;
    char *value = NULL;

    // Create a new JSON object
    root = cJSON_CreateObject();
    if (!root) goto cleanup;

    // Create a new JSON array
    array = cJSON_CreateArray();
    if (!array) goto cleanup;

    // Add the array to the root object with a key derived from fuzz input
    key = safe_strndup(data, size / 2);
    if (!key) goto cleanup;
    if (!cJSON_AddItemToObject(root, key, array)) goto cleanup;

    // Create a string item and add it to the array
    value = safe_strndup(data + size / 2, size - size / 2);
    if (!value) goto cleanup;
    string_item = cJSON_CreateString(value);
    if (!string_item) goto cleanup;
    if (!cJSON_AddItemToArray(array, string_item)) goto cleanup;

    // Create a boolean item and add it to the root object
    bool_item = cJSON_CreateBool(data[0] % 2);
    if (!bool_item) goto cleanup;
    if (!cJSON_AddItemToObject(root, "bool_item", bool_item)) goto cleanup;

    // Add a null item to the root object
    null_item = cJSON_AddNullToObject(root, "null_item");
    if (!null_item) goto cleanup;

    // Cleanup
    cleanup:
    if (root) cJSON_Delete(root);
    if (key) free(key);
    if (value) free(value);

    return 0;
}
