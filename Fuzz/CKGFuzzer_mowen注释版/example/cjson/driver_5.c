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

// Function to safely create a string from fuzz input
cJSON* safe_create_string(const uint8_t *data, size_t size) {
    char *str = safe_strndup(data, size);
    if (!str) return NULL;
    cJSON *item = cJSON_CreateString(str);
    free(str);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there's enough data to work with

    // Initialize variables
    cJSON *root = cJSON_CreateObject();
    if (!root) return 0;

    // Create a boolean item
    cJSON *bool_item = cJSON_CreateBool(data[0] % 2);
    if (!bool_item) {
        cJSON_Delete(root);
        return 0;
    }
    cJSON_AddItemToObject(root, "bool_key", bool_item);

    // Create a null item
    cJSON_AddNullToObject(root, "null_key");

    // Create an array item
    cJSON *array_item = cJSON_CreateArray();
    if (!array_item) {
        cJSON_Delete(root);
        return 0;
    }
    cJSON_AddItemToObject(root, "array_key", array_item);

    // Create a string item
    cJSON *string_item = safe_create_string(data + 1, size - 1);
    if (!string_item) {
        cJSON_Delete(root);
        return 0;
    }
    cJSON_AddItemToObject(root, "string_key", string_item);

    // Clean up
    cJSON_Delete(root);

    return 0;
}
