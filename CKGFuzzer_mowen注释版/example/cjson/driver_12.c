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

// Function to safely create a cJSON item from fuzz input
cJSON* create_cjson_item(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    cJSON *item = cJSON_CreateString((const char*)data);
    if (!item) return NULL;
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0; // Need at least 3 bytes for meaningful operations

    // Initialize variables
    cJSON *root = cJSON_CreateObject();
    if (!root) return 0;

    // Extract key and value from fuzz input
    size_t key_size = size / 2;
    size_t value_size = size - key_size;
    char *key = safe_strndup(data, key_size);
    if (!key) {
        cJSON_Delete(root);
        return 0;
    }
    cJSON *value = create_cjson_item(data + key_size, value_size);
    if (!value) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }

    // Add item to object
    if (cJSON_AddItemToObject(root, key, value) == NULL) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }

    // Detach item from object
    cJSON *detached_item = cJSON_DetachItemFromObjectCaseSensitive(root, key);
    if (detached_item) {
        cJSON_Delete(detached_item);
    }

    // Create a new object and add it to the root object
    cJSON *new_object = cJSON_CreateObject();
    if (!new_object) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }
    if (cJSON_AddItemToObject(root, "new_object", new_object) == NULL) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }

    // Replace an item in the array (simulate an array within the object)
    cJSON *array = cJSON_CreateArray();
    if (!array) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }
    if (cJSON_AddItemToObject(root, "array", array) == NULL) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }
    cJSON *new_item = create_cjson_item(data, size);
    if (!new_item) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }
    if (!cJSON_ReplaceItemInArray(array, 0, new_item)) {
        free(key);
        cJSON_Delete(root);
        return 0;
    }

    // Delete an item from the object
    cJSON_DeleteItemFromObjectCaseSensitive(root, "new_object");

    // Clean up
    free(key);
    cJSON_Delete(root);

    return 0;
}
