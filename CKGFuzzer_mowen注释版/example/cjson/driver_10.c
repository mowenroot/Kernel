#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely get a string from the fuzz input
const char* get_string_from_input(const uint8_t *data, size_t size, size_t *index) {
    if (*index + sizeof(uint32_t) > size) {
        return NULL;
    }
    uint32_t str_len = *(uint32_t*)(data + *index);
    *index += sizeof(uint32_t);
    if (*index + str_len > size) {
        return NULL;
    }
    const char* str = (const char*)(data + *index);
    *index += str_len;
    return str;
}

// Function to safely get an integer from the fuzz input
int get_int_from_input(const uint8_t *data, size_t size, size_t *index) {
    if (*index + sizeof(int) > size) {
        return -1;
    }
    int value = *(int*)(data + *index);
    *index += sizeof(int);
    return value;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON *array = cJSON_CreateArray();
    cJSON *item = NULL;
    cJSON *new_item = NULL;
    cJSON *ref_item = NULL;
    const char *key = NULL;
    int index = 0;
    size_t input_index = 0;

    // Ensure array is created
    if (array == NULL) {
        return 0;
    }

    // Add an item to the array
    item = cJSON_CreateNull();
    if (item == NULL || !cJSON_AddItemToArray(array, item)) {
        cJSON_Delete(array);
        return 0;
    }

    // Replace an item in the array
    index = get_int_from_input(data, size, &input_index);
    if (index >= 0) {
        new_item = cJSON_CreateTrue();
        if (new_item == NULL || !cJSON_ReplaceItemInArray(array, index, new_item)) {
            cJSON_Delete(array);
            return 0;
        }
    }

    // Delete an item from the array
    index = get_int_from_input(data, size, &input_index);
    if (index >= 0) {
        cJSON_DeleteItemFromArray(array, index);
    }

    // Create an array reference
    ref_item = cJSON_CreateArrayReference(array);
    if (ref_item == NULL) {
        cJSON_Delete(array);
        return 0;
    }

    // Add the reference item to the array
    if (!cJSON_AddItemReferenceToArray(array, ref_item)) {
        cJSON_Delete(array);
        cJSON_Delete(ref_item);
        return 0;
    }

    // Detach an item from the array
    index = get_int_from_input(data, size, &input_index);
    if (index >= 0) {
        cJSON_DetachItemFromArray(array, index);
    }

    // Delete an item from the object case-sensitively
    key = get_string_from_input(data, size, &input_index);
    if (key != NULL) {
        cJSON_DeleteItemFromObjectCaseSensitive(array, key);
    }

    // Clean up
    cJSON_Delete(array);
    cJSON_Delete(ref_item);

    return 0;
}
