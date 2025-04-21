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

// Function to safely create a cJSON object from fuzz input
cJSON* create_cjson_object(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = safe_strndup(data, size);
    if (str == NULL) return NULL;
    cJSON *obj = cJSON_Parse(str);
    free(str);
    return obj;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 3) return 0;

    // Create a cJSON object and array
    cJSON *root_object = cJSON_CreateObject();
    cJSON *root_array = cJSON_CreateArray();
    if (root_object == NULL || root_array == NULL) {
        cJSON_Delete(root_object);
        cJSON_Delete(root_array);
        return 0;
    }

    // Create a cJSON item from the fuzz input
    cJSON *item = create_cjson_object(data, size / 2);
    if (item == NULL) {
        cJSON_Delete(root_object);
        cJSON_Delete(root_array);
        return 0;
    }

    // Add the item to the object
    char *key = safe_strndup(data + size / 2, size / 4);
    if (key == NULL) {
        cJSON_Delete(root_object);
        cJSON_Delete(root_array);
        cJSON_Delete(item);
        return 0;
    }
    cJSON_AddItemToObject(root_object, key, item);
    free(key);

    // Create a reference to the item and add it to the array
    cJSON *item_ref = cJSON_CreateObjectReference(item);
    if (item_ref == NULL) {
        cJSON_Delete(root_object);
        cJSON_Delete(root_array);
        return 0;
    }
    cJSON_AddItemReferenceToArray(root_array, item_ref);
    cJSON_Delete(item_ref);

    // Delete an item from the array (if possible)
    if (cJSON_GetArraySize(root_array) > 0) {
        cJSON_DeleteItemFromArray(root_array, 0);
    }

    // Clean up
    cJSON_Delete(root_object);
    cJSON_Delete(root_array);

    return 0;
}
