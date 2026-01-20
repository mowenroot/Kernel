#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size < sizeof(double) + sizeof(int)) {
        return 0;
    }

    // Initialize variables
    cJSON *array = NULL;
    cJSON *number = NULL;
    char *json_str = NULL;

    // Create a cJSON array
    array = cJSON_CreateArray();
    if (array == NULL) {
        goto cleanup;
    }

    // Create a cJSON number from the input data
    double num = *(double *)(data);
    number = cJSON_CreateNumber(num);
    if (number == NULL) {
        goto cleanup;
    }

    // Add the number to the array
    if (!cJSON_AddItemToArray(array, number)) {
        cJSON_Delete(number);
        goto cleanup;
    }

    // Convert the array to an unformatted JSON string
    json_str = cJSON_PrintUnformatted(array);
    if (json_str == NULL) {
        goto cleanup;
    }

    // Delete an item from the array (index derived from input data)
    int index = *(int *)(data + sizeof(double));
    if (index >= 0 && index < cJSON_GetArraySize(array)) {
        cJSON_DeleteItemFromArray(array, index);
    }

    // Cleanup
    free(json_str);

cleanup:
    if (array != NULL) {
        cJSON_Delete(array);
    }

    return 0;
}
