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

// Function to safely convert fuzz input to a double
double safe_atof(const uint8_t *data, size_t size) {
    char *str = safe_strndup(data, size);
    if (!str) return 0.0;
    double num = atof(str);
    free(str);
    return num;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize cJSON object
    cJSON *root = cJSON_CreateObject();
    if (!root) return 0;

    // Create a number item from the first part of the input
    double num = safe_atof(data, size / 2);
    cJSON *number_item = cJSON_CreateNumber(num);
    if (!number_item) {
        cJSON_Delete(root);
        return 0;
    }

    // Create a string item from the second part of the input
    char *str = safe_strndup(data + size / 2, size - size / 2);
    cJSON *string_item = cJSON_CreateString(str);
    free(str);
    if (!string_item) {
        cJSON_Delete(number_item);
        cJSON_Delete(root);
        return 0;
    }

    // Add the number item to the root object
    if (!cJSON_AddItemToObject(root, "number", number_item)) {
        cJSON_Delete(number_item);
        cJSON_Delete(string_item);
        cJSON_Delete(root);
        return 0;
    }

    // Add the string item to the root object
    if (!cJSON_AddItemToObject(root, "string", string_item)) {
        cJSON_Delete(string_item);
        cJSON_Delete(root);
        return 0;
    }

    // Check if the added items are of the correct type
    cJSON *number_check = cJSON_GetObjectItem(root, "number");
    cJSON *string_check = cJSON_GetObjectItem(root, "string");

    if (cJSON_IsNumber(number_check) && cJSON_IsString(string_check)) {
        // If both items are of the correct type, delete the string item from the object
        cJSON_DeleteItemFromObject(root, "string");
    }

    // Clean up
    cJSON_Delete(root);

    return 0;
}
