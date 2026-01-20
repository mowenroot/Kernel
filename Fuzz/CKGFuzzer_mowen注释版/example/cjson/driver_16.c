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
    if (*offset + sizeof(int) > size) return 0;
    int value = *(int*)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2) return 0; // Need at least two integers for array index and object key length

    size_t offset = 0;
    int array_index = safe_get_int(data, size, &offset);
    int key_length = safe_get_int(data, size, &offset);

    if (offset + key_length > size) return 0; // Ensure key length does not exceed input size

    char *key = safe_strndup(data + offset, key_length);
    offset += key_length;

    // Create a JSON array
    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        free(key);
        return 0;
    }

    // Create a JSON object
    cJSON *object = cJSON_CreateObject();
    if (object == NULL) {
        cJSON_Delete(array);
        free(key);
        return 0;
    }

    // Get array item by index
    cJSON *array_item = cJSON_GetArrayItem(array, array_index);
    if (array_item != NULL) {
        // Handle array item if found (not expected in this context)
    }

    // Get array size
    int array_size = cJSON_GetArraySize(array);
    if (array_size < 0) {
        // Handle error in array size (not expected in this context)
    }

    // Get object item by key
    cJSON *object_item = cJSON_GetObjectItemCaseSensitive(object, key);
    if (object_item != NULL) {
        // Handle object item if found (not expected in this context)
    }

    // Get error pointer (if any)
    const char *error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL) {
        // Handle parsing error
    }

    // Clean up
    cJSON_Delete(array);
    cJSON_Delete(object);
    free(key);

    return 0;
}
