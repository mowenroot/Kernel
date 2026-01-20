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
    if (size < 3) return 0;

    // Initialize variables
    cJSON *root = cJSON_CreateObject();
    if (!root) return 0; // Early exit if object creation fails

    // Extract key and value strings from fuzz input
    size_t key_size = data[0];
    size_t value_size = data[1];
    if (key_size + value_size + 2 > size) {
        cJSON_Delete(root);
        return 0; // Early exit if input is malformed
    }

    char *key = safe_strndup(data + 2, key_size);
    char *value = safe_strndup(data + 2 + key_size, value_size);

    if (!key || !value) {
        free(key);
        free(value);
        cJSON_Delete(root);
        return 0; // Early exit if string duplication fails
    }

    // Create a string item and add it to the object
    cJSON *string_item = cJSON_CreateString(value);
    if (!string_item) {
        free(key);
        free(value);
        cJSON_Delete(root);
        return 0; // Early exit if string item creation fails
    }

    if (!cJSON_AddItemToObject(root, key, string_item)) {
        free(key);
        free(value);
        cJSON_Delete(root);
        return 0; // Early exit if adding item to object fails
    }

    // Replace the item in the object
    cJSON *new_string_item = cJSON_CreateString("replacement");
    if (!new_string_item) {
        free(key);
        free(value);
        cJSON_Delete(root);
        return 0; // Early exit if new string item creation fails
    }

    if (!cJSON_ReplaceItemInObjectCaseSensitive(root, key, new_string_item)) {
        free(key);
        free(value);
        cJSON_Delete(root);
        return 0; // Early exit if replacing item in object fails
    }

    // Delete the item from the object
    cJSON_DeleteItemFromObjectCaseSensitive(root, key);

    // Clean up
    free(key);
    free(value);
    cJSON_Delete(root);

    return 0; // Return 0 to indicate success
}
