#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely get an integer from the fuzz input
int get_int_from_data(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(int) > size) {
        return -1; // Not enough data for an int
    }
    int value = *(int*)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Function to safely get a cJSON item from the fuzz input
cJSON *get_cjson_item_from_data(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(cJSON) > size) {
        return NULL; // Not enough data for a cJSON item
    }
    cJSON *item = (cJSON*)(data + *offset);
    *offset += sizeof(cJSON);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cJSON *array = NULL;
    cJSON *item = NULL;
    int index = 0;

    // Create a new cJSON array
    array = cJSON_CreateArray();
    if (array == NULL) {
        return 0; // Failed to create array
    }

    // Add an item to the array
    item = cJSON_CreateNull(); // Example item creation
    if (item == NULL) {
        cJSON_Delete(array);
        return 0; // Failed to create item
    }
    if (!cJSON_AddItemToArray(array, item)) {
        cJSON_Delete(array);
        cJSON_Delete(item);
        return 0; // Failed to add item to array
    }

    // Replace an item in the array
    index = get_int_from_data(data, size, &offset);
    if (index >= 0) {
        cJSON *new_item = cJSON_CreateTrue(); // Example new item creation
        if (new_item == NULL) {
            cJSON_Delete(array);
            return 0; // Failed to create new item
        }
        if (!cJSON_ReplaceItemInArray(array, index, new_item)) {
            cJSON_Delete(array);
            cJSON_Delete(new_item);
            return 0; // Failed to replace item in array
        }
    }

    // Detach an item from the array
    index = get_int_from_data(data, size, &offset);
    if (index >= 0) {
        cJSON *detached_item = cJSON_DetachItemFromArray(array, index);
        if (detached_item != NULL) {
            cJSON_Delete(detached_item); // Free the detached item
        }
    }

    // Delete an item from the array
    index = get_int_from_data(data, size, &offset);
    if (index >= 0) {
        cJSON_DeleteItemFromArray(array, index);
    }

    // Clean up
    cJSON_Delete(array);

    return 0;
}
