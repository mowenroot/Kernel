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
    cJSON *obj = cJSON_New_Item();
    if (obj == NULL) return NULL;
    obj->type = cJSON_Object;
    return obj;
}

// Function to safely create a cJSON array from fuzz input
cJSON* create_cjson_array(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    cJSON *arr = cJSON_New_Item();
    if (arr == NULL) return NULL;
    arr->type = cJSON_Array;
    return arr;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize variables
    cJSON *root = NULL;
    cJSON *array = NULL;
    cJSON *object = NULL;
    cJSON *item = NULL;
    char *key = NULL;
    int index = 0;

    // Create a root object
    root = create_cjson_object(data, size);
    if (root == NULL) goto cleanup;

    // Create an array
    array = create_cjson_array(data, size);
    if (array == NULL) goto cleanup;

    // Create an object
    object = create_cjson_object(data, size);
    if (object == NULL) goto cleanup;

    // Create a key from the fuzz input
    key = safe_strndup(data, size / 4);
    if (key == NULL) goto cleanup;

    // Create an item
    item = create_cjson_object(data, size);
    if (item == NULL) goto cleanup;

    // Add item to object
    if (cJSON_AddItemToObject(object, key, item) == NULL) goto cleanup;

    // Add item reference to array
    if (!cJSON_AddItemReferenceToArray(array, item)) goto cleanup;

    // Create array reference
    cJSON *array_ref = cJSON_CreateArrayReference(array);
    if (array_ref == NULL) goto cleanup;

    // Add array reference to root
    if (cJSON_AddItemToObject(root, "array_ref", array_ref) == NULL) goto cleanup;

    // Create object reference
    cJSON *object_ref = cJSON_CreateObjectReference(object);
    if (object_ref == NULL) goto cleanup;

    // Add object reference to root
    if (cJSON_AddItemToObject(root, "object_ref", object_ref) == NULL) goto cleanup;

    // Add item to array
    if (cJSON_AddItemToArray(array, item) == NULL) goto cleanup;

    // Delete item from array
    index = data[size - 1] % cJSON_GetArraySize(array);
    cJSON_DeleteItemFromArray(array, index);

cleanup:
    // Free all allocated resources
    if (root != NULL) cJSON_Delete(root);
    if (array != NULL) cJSON_Delete(array);
    if (object != NULL) cJSON_Delete(object);
    if (item != NULL) cJSON_Delete(item);
    if (key != NULL) free(key);

    return 0;
}
