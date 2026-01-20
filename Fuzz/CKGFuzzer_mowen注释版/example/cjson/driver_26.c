#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely get an integer from the fuzz input
int get_int_from_data(const uint8_t *data, size_t size, size_t *offset, int max_value) {
    if (*offset + sizeof(int) > size) {
        return -1; // Not enough data
    }
    int value = *(int *)(data + *offset);
    *offset += sizeof(int);
    if (value < 0 || value > max_value) {
        return -1; // Invalid value
    }
    return value;
}

// Function to safely get a cJSON item from the fuzz input
cJSON *get_cjson_item_from_data(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(cJSON) > size) {
        return NULL; // Not enough data
    }
    cJSON *item = (cJSON *)(data + *offset);
    *offset += sizeof(cJSON);
    return item;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t offset = 0;

    // Initialize a cJSON array
    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        return 0; // Failed to create array
    }

    // Get the number of items to add to the array
    int num_items = get_int_from_data(data, size, &offset, 100); // Limit to 100 items
    if (num_items < 0) {
        cJSON_Delete(array);
        return 0; // Invalid number of items
    }

    // Add items to the array
    for (int i = 0; i < num_items; i++) {
        cJSON *item = get_cjson_item_from_data(data, size, &offset);
        if (item == NULL) {
            cJSON_Delete(array);
            return 0; // Invalid item
        }
        cJSON_AddItemToArray(array, item);
    }

    // Get the array size
    int array_size = cJSON_GetArraySize(array);
    if (array_size < 0) {
        cJSON_Delete(array);
        return 0; // Invalid array size
    }

    // Get an item from the array
    int index = get_int_from_data(data, size, &offset, array_size - 1);
    if (index < 0) {
        cJSON_Delete(array);
        return 0; // Invalid index
    }
    cJSON *array_item = cJSON_GetArrayItem(array, index);
    if (array_item == NULL) {
        cJSON_Delete(array);
        return 0; // Item not found
    }

    // Create an array reference
    cJSON *array_ref = cJSON_CreateArrayReference(array_item);
    if (array_ref == NULL) {
        cJSON_Delete(array);
        return 0; // Failed to create array reference
    }

    // Delete an item from the array
    int delete_index = get_int_from_data(data, size, &offset, array_size - 1);
    if (delete_index < 0) {
        cJSON_Delete(array_ref);
        cJSON_Delete(array);
        return 0; // Invalid delete index
    }
    cJSON_DeleteItemFromArray(array, delete_index);

    // Clean up
    cJSON_Delete(array_ref);
    cJSON_Delete(array);

    return 0;
}
