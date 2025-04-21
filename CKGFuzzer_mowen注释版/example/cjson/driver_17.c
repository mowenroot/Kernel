#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely get an integer from the fuzz input
int get_int_from_data(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(int) > size) {
        return -1; // Return an invalid index if not enough data
    }
    int value = *(int *)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Function to safely get a string from the fuzz input
char *get_string_from_data(const uint8_t *data, size_t size, size_t *offset, size_t max_len) {
    if (*offset + max_len > size) {
        return NULL; // Return NULL if not enough data
    }
    char *str = (char *)malloc(max_len + 1);
    if (!str) {
        return NULL; // Return NULL if malloc fails
    }
    memcpy(str, data + *offset, max_len);
    str[max_len] = '\0';
    *offset += max_len;
    return str;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cJSON *root = cJSON_CreateArray();
    if (!root) {
        return 0; // Early exit if memory allocation fails
    }

    size_t offset = 0;
    int index;
    char *str;
    cJSON *item;

    // Add an item to the array
    str = get_string_from_data(data, size, &offset, 10); // Limit string length to 10
    if (str) {
        item = cJSON_CreateString(str);
        if (item) {
            cJSON_AddItemToArray(root, item);
        }
        free(str);
    }

    // Insert an item into the array
    index = get_int_from_data(data, size, &offset);
    str = get_string_from_data(data, size, &offset, 10);
    if (str) {
        item = cJSON_CreateString(str);
        if (item) {
            cJSON_InsertItemInArray(root, index, item);
        }
        free(str);
    }

    // Replace an item in the array
    index = get_int_from_data(data, size, &offset);
    str = get_string_from_data(data, size, &offset, 10);
    if (str) {
        item = cJSON_CreateString(str);
        if (item) {
            cJSON_ReplaceItemInArray(root, index, item);
        }
        free(str);
    }

    // Get an item from the array
    index = get_int_from_data(data, size, &offset);
    item = cJSON_GetArrayItem(root, index);
    if (item) {
        // Do something with the item, e.g., print its value
    }

    // Delete an item from the array
    index = get_int_from_data(data, size, &offset);
    cJSON_DeleteItemFromArray(root, index);

    // Detach an item from the array
    index = get_int_from_data(data, size, &offset);
    item = cJSON_DetachItemFromArray(root, index);
    if (item) {
        cJSON_Delete(item); // Free the detached item
    }

    // Clean up
    cJSON_Delete(root);

    return 0; // Non-zero return values are reserved for future use.
}
