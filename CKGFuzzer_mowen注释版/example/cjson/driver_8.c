#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a cJSON object from fuzz input
cJSON* create_cjson_from_input(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = safe_strndup(data, size);
    if (!str) return NULL;
    cJSON *item = cJSON_CreateString(str);
    free(str);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

    // Initialize variables
    cJSON *array = cJSON_CreateArray();
    cJSON *bool_item = cJSON_CreateBool(data[0] % 2); // Create a boolean item
    cJSON *string_item = create_cjson_from_input(data, size); // Create a string item
    cJSON *array_ref = cJSON_CreateArrayReference(array); // Create an array reference
    cJSON *string_ref = cJSON_CreateStringReference((const char*)data); // Create a string reference
    cJSON *object_ref = cJSON_CreateObjectReference(array); // Create an object reference

    // Error handling for item creation
    if (!array || !bool_item || !string_item || !array_ref || !string_ref || !object_ref) {
        cJSON_Delete(array);
        cJSON_Delete(bool_item);
        cJSON_Delete(string_item);
        cJSON_Delete(array_ref);
        cJSON_Delete(string_ref);
        cJSON_Delete(object_ref);
        return 0;
    }

    // Add items to the array
    if (!cJSON_AddItemReferenceToArray(array, bool_item) ||
        !cJSON_AddItemReferenceToArray(array, string_item) ||
        !cJSON_AddItemReferenceToArray(array, array_ref) ||
        !cJSON_AddItemReferenceToArray(array, string_ref) ||
        !cJSON_AddItemReferenceToArray(array, object_ref)) {
        cJSON_Delete(array);
        cJSON_Delete(bool_item);
        cJSON_Delete(string_item);
        cJSON_Delete(array_ref);
        cJSON_Delete(string_ref);
        cJSON_Delete(object_ref);
        return 0;
    }

    // Clean up
    cJSON_Delete(array);
    cJSON_Delete(bool_item);
    cJSON_Delete(string_item);
    cJSON_Delete(array_ref);
    cJSON_Delete(string_ref);
    cJSON_Delete(object_ref);

    return 0;
}
