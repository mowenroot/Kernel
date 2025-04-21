#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to create a cJSON object from fuzz input
cJSON* create_cjson_object_from_input(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        size = 1024;
    }

    // Create a buffer to hold the JSON string
    char json_str[1025];
    memset(json_str, 0, sizeof(json_str));

    // Copy the fuzz input into the buffer
    memcpy(json_str, data, size);

    // Parse the JSON string into a cJSON object
    cJSON *json = cJSON_Parse(json_str);
    if (json == NULL) {
        // Handle parsing error
        return NULL;
    }

    return json;
}

// Function to safely get a string from fuzz input
const char* get_string_from_input(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent buffer overflow
    if (size > 1024) {
        size = 1024;
    }

    // Create a buffer to hold the string
    char *str = (char*)malloc(size + 1);
    if (str == NULL) {
        // Handle allocation error
        return NULL;
    }

    // Copy the fuzz input into the buffer
    memcpy(str, data, size);
    str[size] = '\0'; // Null-terminate the string

    return str;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size < 2) {
        return 0;
    }

    // Create a cJSON object from the fuzz input
    cJSON *json = create_cjson_object_from_input(data, size / 2);
    if (json == NULL) {
        return 0;
    }

    // Get a string from the fuzz input for object key
    const char *key = get_string_from_input(data + size / 2, size / 2);
    if (key == NULL) {
        cJSON_Delete(json);
        return 0;
    }

    // Test cJSON_DetachItemFromObjectCaseSensitive
    cJSON *detached_item = cJSON_DetachItemFromObjectCaseSensitive(json, key);
    if (detached_item != NULL) {
        cJSON_Delete(detached_item); // Free the detached item
    }

    // Test cJSON_DeleteItemFromObjectCaseSensitive
    cJSON_DeleteItemFromObjectCaseSensitive(json, key);

    // Test cJSON_DeleteItemFromArray
    int index = (int)(data[0] % 10); // Use a small index to prevent out-of-bounds access
    cJSON_DeleteItemFromArray(json, index);

    // Test cJSON_DetachItemFromArray
    detached_item = cJSON_DetachItemFromArray(json, index);
    if (detached_item != NULL) {
        cJSON_Delete(detached_item); // Free the detached item
    }

    // Clean up
    cJSON_Delete(json);
    free((void*)key);

    return 0;
}
