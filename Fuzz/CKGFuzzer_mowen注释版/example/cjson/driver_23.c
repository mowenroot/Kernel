#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (str == NULL) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely get an integer from fuzz input
int safe_get_int(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(int) > size) return -1;
    int value = *(int*)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 3) return 0; // Need at least 3 integers for our operations

    size_t offset = 0;
    int index1 = safe_get_int(data, size, &offset);
    int index2 = safe_get_int(data, size, &offset);
    int index3 = safe_get_int(data, size, &offset);

    // Create a sample JSON object
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return 0;

    // Add some items to the object
    cJSON_AddItemToObject(root, "key1", cJSON_CreateString("value1"));
    cJSON_AddItemToObject(root, "key2", cJSON_CreateString("value2"));

    // Create a sample JSON array
    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        cJSON_Delete(root);
        return 0;
    }
    cJSON_AddItemToArray(array, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(array, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(array, cJSON_CreateNumber(3));

    // Detach an item from the object
    cJSON *detached_item = cJSON_DetachItemFromObjectCaseSensitive(root, "key1");
    if (detached_item != NULL) {
        cJSON_Delete(detached_item);
    }

    // Replace an item in the array
    cJSON *new_item = cJSON_CreateNumber(4);
    if (new_item != NULL) {
        if (!cJSON_ReplaceItemInArray(array, index1, new_item)) {
            cJSON_Delete(new_item);
        }
    }

    // Delete an item from the array
    cJSON_DeleteItemFromArray(array, index2);

    // Replace an item in the object
    cJSON *new_item_obj = cJSON_CreateString("new_value");
    if (new_item_obj != NULL) {
        if (!cJSON_ReplaceItemInObjectCaseSensitive(root, "key2", new_item_obj)) {
            cJSON_Delete(new_item_obj);
        }
    }

    // Detach an item from the array
    cJSON *detached_array_item = cJSON_DetachItemFromArray(array, index3);
    if (detached_array_item != NULL) {
        cJSON_Delete(detached_array_item);
    }

    // Clean up
    cJSON_Delete(root);
    cJSON_Delete(array);

    return 0;
}
