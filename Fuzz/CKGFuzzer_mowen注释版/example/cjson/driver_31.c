#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for at least one string key and value
    if (size < 2) return 0;

    // Calculate the size of the key and value strings
    size_t key_size = size / 2;
    size_t value_size = size - key_size;

    // Create a new cJSON object
    cJSON* json_object = cJSON_CreateObject();
    if (!json_object) return 0; // Failed to create object

    // Create a string key from the fuzz input
    char* key = safe_strndup(data, key_size);
    if (!key) {
        cJSON_Delete(json_object);
        return 0; // Failed to allocate key
    }

    // Create a string value from the fuzz input
    char* value = safe_strndup(data + key_size, value_size);
    if (!value) {
        free(key);
        cJSON_Delete(json_object);
        return 0; // Failed to allocate value
    }

    // Create a cJSON string item from the value
    cJSON* json_string = cJSON_CreateString(value);
    if (!json_string) {
        free(key);
        free(value);
        cJSON_Delete(json_object);
        return 0; // Failed to create string item
    }

    // Add the string item to the object with the key
    cJSON_AddItemToObject(json_object, key, json_string);

    // Detach the item from the object (for testing the detach function)
    cJSON* detached_item = cJSON_DetachItemFromObjectCaseSensitive(json_object, key);
    if (detached_item) {
        cJSON_Delete(detached_item); // Clean up the detached item
    }

    // Delete the item from the object (for testing the delete function)
    cJSON_DeleteItemFromObjectCaseSensitive(json_object, key);

    // Clean up
    free(key);
    free(value);
    cJSON_Delete(json_object);

    return 0; // Return 0 to indicate success
}
