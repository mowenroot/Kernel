#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to an integer
int safe_convert_to_int(const uint8_t *data, size_t size, size_t *index) {
    if (*index >= size) return 0;
    int result = 0;
    while (*index < size && data[*index] >= '0' && data[*index] <= '9') {
        result = result * 10 + (data[*index] - '0');
        (*index)++;
    }
    return result;
}

// Function to safely create a cJSON item from fuzz input
cJSON* safe_create_cjson_item(const uint8_t *data, size_t size, size_t *index) {
    if (*index >= size) return NULL;
    size_t length = 0;
    while (*index + length < size && data[*index + length] != '\0') {
        length++;
    }
    if (length == 0) return NULL;
    char *str = (char*)malloc(length + 1);
    if (!str) return NULL;
    memcpy(str, data + *index, length);
    str[length] = '\0';
    *index += length;
    cJSON *item = cJSON_CreateString(str);
    free(str);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Need at least 2 bytes for meaningful input

    // Initialize variables
    cJSON *array = NULL;
    cJSON *item = NULL;
    cJSON *detached_item = NULL;
    int index = 0;
    size_t index_offset = 0;

    // Create an array
    array = cJSON_CreateArray();
    if (!array) return 0;

    // Add an item to the array
    index_offset++; // Move past the first byte
    item = safe_create_cjson_item(data, size, &index_offset);
    if (item) {
        cJSON_AddItemToArray(array, item);
    }

    // Get an item from the array
    index = safe_convert_to_int(data, size, &index_offset);
    if (index >= 0) {
        cJSON *array_item = cJSON_GetArrayItem(array, index);
        if (array_item) {
            // Do something with array_item if needed
        }
    }

    // Replace an item in the array
    index = safe_convert_to_int(data, size, &index_offset);
    if (index >= 0) {
        item = safe_create_cjson_item(data, size, &index_offset);
        if (item) {
            cJSON_ReplaceItemInArray(array, index, item);
        }
    }

    // Detach an item from the array
    index = safe_convert_to_int(data, size, &index_offset);
    if (index >= 0) {
        detached_item = cJSON_DetachItemFromArray(array, index);
        if (detached_item) {
            cJSON_Delete(detached_item); // Free the detached item
        }
    }

    // Clean up
    cJSON_Delete(array); // Free the array and all its items

    return 0;
}
