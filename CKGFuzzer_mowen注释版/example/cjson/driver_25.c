#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a string
char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely parse JSON from fuzz input
cJSON* safe_parse_json(const uint8_t *data, size_t size) {
    char *json_str = safe_strndup(data, size);
    if (!json_str) return NULL;
    cJSON *json = cJSON_Parse(json_str);
    free(json_str);
    return json;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure input size is reasonable to prevent excessive memory usage
    if (size > 1024) return 0;

    // Parse the input data as JSON
    cJSON *json = safe_parse_json(data, size);
    if (!json) return 0;

    // Create a new array to manipulate
    cJSON *new_array = cJSON_CreateArray();
    if (!new_array) {
        cJSON_Delete(json);
        return 0;
    }

    // Get the size of the parsed JSON array
    int array_size = cJSON_GetArraySize(json);
    if (array_size < 0) {
        cJSON_Delete(json);
        cJSON_Delete(new_array);
        return 0;
    }

    // Iterate through the parsed JSON array and add items to the new array
    for (int i = 0; i < array_size; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        if (item) {
            cJSON_AddItemToArray(new_array, cJSON_Duplicate(item, 1));
        }
    }

    // Delete an item from the new array (if possible)
    if (array_size > 0) {
        cJSON_DeleteItemFromArray(new_array, 0);
    }

    // Clean up
    cJSON_Delete(json);
    cJSON_Delete(new_array);

    return 0;
}
