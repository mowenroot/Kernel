#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Create a cJSON array
    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        return 0;
    }

    // Add items to the array based on the input data
    for (size_t i = 0; i < size; i++) {
        cJSON *item = cJSON_CreateNumber(data[i]);
        if (item == NULL) {
            cJSON_Delete(array);
            return 0;
        }
        cJSON_AddItemToArray(array, item);
    }

    // Get the size of the array
    int array_size = cJSON_GetArraySize(array);
    if (array_size < 0) {
        cJSON_Delete(array);
        return 0;
    }

    // Perform operations on the array
    if (array_size > 0) {
        // Get an item from the array
        cJSON *item = cJSON_GetArrayItem(array, 0);
        if (item == NULL) {
            cJSON_Delete(array);
            return 0;
        }

        // Detach an item from the array
        cJSON *detached_item = cJSON_DetachItemFromArray(array, 0);
        if (detached_item != NULL) {
            cJSON_Delete(detached_item);
        }

        // Replace an item in the array
        cJSON *new_item = cJSON_CreateNumber(42);
        if (new_item == NULL) {
            cJSON_Delete(array);
            return 0;
        }
        if (!cJSON_ReplaceItemInArray(array, 0, new_item)) {
            cJSON_Delete(new_item);
            cJSON_Delete(array);
            return 0;
        }

        // Delete an item from the array
        cJSON_DeleteItemFromArray(array, 0);
    }

    // Clean up
    cJSON_Delete(array);

    return 0;
}
