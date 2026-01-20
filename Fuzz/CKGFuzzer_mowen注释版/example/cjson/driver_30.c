#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h> // Include stdbool.h to use bool type

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL; // Replace nullptr with NULL
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL; // Replace nullptr with NULL
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely get an integer from fuzz input
int safe_get_int(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(int) > size) return 0;
    return *((int*)(data + offset)); // Correct pointer dereference
}

// Function to safely get a boolean from fuzz input
bool safe_get_bool(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(bool) > size) return false; // Correct usage of bool and false
    return *((bool*)(data + offset)); // Correct pointer dereference
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { // Remove extern "C"
    // Ensure we have enough data to proceed
    if (size < sizeof(int) + sizeof(bool) + 1) return 0;

    // Extract input parameters from fuzz data
    size_t offset = 0;
    int buffer_size = safe_get_int(data, size, offset);
    offset += sizeof(int);
    bool format = safe_get_bool(data, size, offset);
    offset += sizeof(bool);
    char* key = safe_strndup(data + offset, size - offset);
    if (!key) return 0;

    // Create a new JSON object
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        free(key);
        return 0;
    }

    // Create a true value item
    cJSON* true_item = cJSON_CreateTrue();
    if (!true_item) {
        cJSON_Delete(root);
        free(key);
        return 0;
    }

    // Add the true item to the object
    if (!cJSON_AddItemToObject(root, key, true_item)) {
        cJSON_Delete(root);
        free(key);
        return 0;
    }

    // Replace the true item with another true item (case sensitive)
    cJSON* new_true_item = cJSON_CreateTrue();
    if (!new_true_item) {
        cJSON_Delete(root);
        free(key);
        return 0;
    }

    if (!cJSON_ReplaceItemInObjectCaseSensitive(root, key, new_true_item)) {
        cJSON_Delete(root);
        free(key);
        return 0;
    }

    // Print the JSON object to a buffered string
    char* json_str = cJSON_PrintBuffered(root, buffer_size, format);
    if (json_str) {
        free(json_str);
    }

    // Clean up
    cJSON_Delete(root);
    free(key);

    return 0;
}
