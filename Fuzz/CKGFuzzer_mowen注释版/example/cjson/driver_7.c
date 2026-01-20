#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely get a boolean value from the fuzz input
cJSON_bool get_boolean_from_input(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + 1 > size) {
        return 0; // Default to false if not enough data
    }
    cJSON_bool value = data[*offset] & 0x01; // Use the least significant bit
    *offset += 1;
    return value;
}

// Function to safely get a string from the fuzz input
char* get_string_from_input(const uint8_t *data, size_t size, size_t *offset, size_t max_length) {
    if (*offset >= size) {
        return NULL; // No data left
    }
    size_t length = 0;
    while (*offset + length < size && length < max_length && data[*offset + length] != '\0') {
        length++;
    }
    if (length == 0) {
        return NULL; // Empty string
    }
    char *str = (char*)malloc(length + 1);
    if (!str) {
        return NULL; // Allocation failed
    }
    memcpy(str, data + *offset, length);
    str[length] = '\0';
    *offset += length;
    return str;
}

// Function to safely get a cJSON object from the fuzz input
cJSON* get_cjson_object_from_input(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset >= size) {
        return NULL; // No data left
    }
    // For simplicity, assume the next byte indicates the type of cJSON object
    uint8_t type = data[*offset];
    *offset += 1;
    switch (type % 6) {
        case 0: return cJSON_CreateBool(get_boolean_from_input(data, size, offset));
        case 1: return cJSON_CreateString(get_string_from_input(data, size, offset, 1024));
        case 2: return cJSON_CreateArrayReference(get_cjson_object_from_input(data, size, offset));
        case 3: return cJSON_CreateStringReference(get_string_from_input(data, size, offset, 1024));
        case 4: return cJSON_CreateNull();
        case 5: return cJSON_CreateObjectReference(get_cjson_object_from_input(data, size, offset));
        default: return NULL; // Should never happen
    }
}

// The main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t offset = 0;

    // Create a cJSON object based on the fuzz input
    cJSON *root = get_cjson_object_from_input(data, size, &offset);
    if (!root) {
        return 0; // Failed to create cJSON object
    }

    // Ensure all allocated resources are freed
    cJSON_Delete(root);

    return 0;
}
