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

// Function to safely create a cJSON item from fuzz input
cJSON* safe_cJSON_Parse(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return NULL;
    cJSON* item = cJSON_Parse(str);
    free(str);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within reasonable limits to prevent excessive memory usage
    if (size > 1024) return 0;

    // Initialize variables
    cJSON* root = NULL;
    cJSON* child = NULL;
    char* json_str = NULL;

    // Create a new cJSON object
    root = cJSON_CreateObject();
    if (!root) return 0;

    // Parse a JSON string from fuzz input and add it to the object
    child = safe_cJSON_Parse(data, size);
    if (child) {
        cJSON_AddItemToObject(root, "fuzz_input", child);
    }

    // Convert the cJSON object to a string
    json_str = cJSON_Print(root);
    if (json_str) {
        // Perform any desired operations with json_str here
        free(json_str);
    }

    // Clean up the cJSON object
    cJSON_Delete(root);

    return 0;
}
