#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a double
double safe_atof(const uint8_t *data, size_t size) {
    char buffer[32]; // Assuming a reasonable size for a double string representation
    size_t len = size < sizeof(buffer) - 1 ? size : sizeof(buffer) - 1;
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    return atof(buffer);
}

// Function to safely convert fuzz input to a string
char* safe_strndup(const uint8_t *data, size_t size) {
    size_t len = size < 1024 ? size : 1024; // Limit string length to prevent excessive memory usage
    char *str = (char*)malloc(len + 1);
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON *root = NULL;
    cJSON *item = NULL;
    char *str = NULL;
    double num = 0.0;

    // Ensure we have enough data to proceed
    if (size < 1) {
        return 0;
    }

    // Create a cJSON object
    root = cJSON_CreateObject();
    if (!root) {
        goto cleanup;
    }

    // Add a false value to the object
    item = cJSON_CreateFalse();
    if (!item) {
        goto cleanup;
    }
    cJSON_AddItemToObject(root, "false_value", item);

    // Add a true value to the object
    item = cJSON_CreateTrue();
    if (!item) {
        goto cleanup;
    }
    cJSON_AddItemToObject(root, "true_value", item);

    // Add a null value to the object
    item = cJSON_CreateNull();
    if (!item) {
        goto cleanup;
    }
    cJSON_AddItemToObject(root, "null_value", item);

    // Add a number value to the object
    num = safe_atof(data, size);
    item = cJSON_CreateNumber(num);
    if (!item) {
        goto cleanup;
    }
    cJSON_AddItemToObject(root, "number_value", item);

    // Add a string value to the object
    str = safe_strndup(data, size);
    if (!str) {
        goto cleanup;
    }
    item = cJSON_CreateString(str);
    if (!item) {
        free(str);
        goto cleanup;
    }
    cJSON_AddItemToObject(root, "string_value", item);

    // Clean up
cleanup:
    if (root) {
        cJSON_Delete(root);
    }
    if (str) {
        free(str);
    }

    return 0;
}
