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

// Function to safely create a cJSON string item from fuzz input
cJSON* create_cjson_string(const uint8_t *data, size_t size) {
    char *str = safe_strndup(data, size);
    if (!str) return NULL;
    cJSON *item = cJSON_CreateString(str);
    free(str);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Need at least 2 bytes for meaningful input

    // Initialize cJSON objects and arrays
    cJSON *root = cJSON_CreateObject();
    if (!root) return 0;

    cJSON *array = cJSON_CreateArray();
    if (!array) {
        cJSON_Delete(root);
        return 0;
    }

    // Add items to the object and array
    cJSON *item1 = create_cjson_string(data, size / 2);
    if (item1) {
        if (!cJSON_AddItemToObject(root, "key1", item1)) {
            cJSON_Delete(item1);
        }
    }

    cJSON *item2 = create_cjson_string(data + size / 2, size - size / 2);
    if (item2) {
        if (!cJSON_AddItemToArray(array, item2)) {
            cJSON_Delete(item2);
        }
    }

    // Add null to the object
    if (!cJSON_AddNullToObject(root, "null_key")) {
        // Handle error if needed
    }

    // Add item to object with constant string key
    cJSON *item3 = cJSON_CreateString("constant_value");
    if (item3) {
        if (!cJSON_AddItemToObjectCS(root, "constant_key", item3)) {
            cJSON_Delete(item3);
        }
    }

    // Add array to the root object
    if (!cJSON_AddItemToObject(root, "array", array)) {
        cJSON_Delete(array);
    }

    // Clean up
    cJSON_Delete(root);

    return 0;
}
