#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely get an integer from the fuzz input
int get_int_from_data(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(int) > size) {
        return -1; // Not enough data for an int
    }
    int value = *(int *)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Function to safely get a cJSON item from the fuzz input
cJSON *get_cjson_item_from_data(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(cJSON) > size) {
        return NULL; // Not enough data for a cJSON item
    }
    cJSON *item = (cJSON *)(data + *offset);
    *offset += sizeof(cJSON);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON *array = NULL;
    cJSON *item = NULL;
    int index = 0;
    size_t offset = 0;

    // Create a new cJSON array
    array = cJSON_CreateArray();
    if (array == NULL) {
        goto cleanup;
    }

    // Add an item to the array
    item = cJSON_CreateNull(); // Example item creation
    if (item == NULL) {
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(array, item)) {
        cJSON_Delete(item);
        goto cleanup;
    }

    // Get the array size
    int array_size = cJSON_GetArraySize(array);
    if (array_size < 0) {
        goto cleanup;
    }

    // Replace an item in the array
    index = get_int_from_data(data, size, &offset);
    if (index < 0 || index >= array_size) {
        goto cleanup;
    }
    cJSON *new_item = cJSON_CreateTrue(); // Example new item creation
    if (new_item == NULL) {
        goto cleanup;
    }
    if (!cJSON_ReplaceItemInArray(array, index, new_item)) {
        cJSON_Delete(new_item);
        goto cleanup;
    }

    // Delete an item from the array
    index = get_int_from_data(data, size, &offset);
    if (index < 0 || index >= array_size) {
        goto cleanup;
    }
    cJSON_DeleteItemFromArray(array, index);

    // Get an item from the array
    index = get_int_from_data(data, size, &offset);
    if (index < 0 || index >= array_size) {
        goto cleanup;
    }
    cJSON *retrieved_item = cJSON_GetArrayItem(array, index);
    if (retrieved_item == NULL) {
        goto cleanup;
    }

cleanup:
    // Free the array and all its items
    if (array != NULL) {
        cJSON_Delete(array);
    }

    return 0;
}
