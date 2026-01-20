#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a string from the fuzz input
const char* safe_extract_string(const uint8_t *data, size_t size, size_t *len) {
    if (size == 0) {
        *len = 0;
        return NULL;
    }

    *len = size - 1; // Exclude the null terminator
    return (const char*)data;
}

// Function to safely extract a boolean from the fuzz input
cJSON_bool safe_extract_bool(const uint8_t *data, size_t size) {
    if (size == 0) {
        return cJSON_False;
    }

    return (*data != 0) ? cJSON_True : cJSON_False;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Initialize variables
    cJSON *json_bool = NULL;
    cJSON *json_string = NULL;
    cJSON *json_array_ref = NULL;
    cJSON *json_string_ref = NULL;
    cJSON *json_object = NULL;
    cJSON *json_object_ref = NULL;

    // Extract a string from the fuzz input
    size_t str_len;
    const char *str = safe_extract_string(data, size, &str_len);

    // Create a boolean JSON item
    json_bool = cJSON_CreateBool(safe_extract_bool(data, size));
    if (!json_bool) {
        goto cleanup;
    }

    // Create a string JSON item
    json_string = cJSON_CreateString(str);
    if (!json_string) {
        goto cleanup;
    }

    // Create an array reference JSON item
    json_array_ref = cJSON_CreateArrayReference(json_bool);
    if (!json_array_ref) {
        goto cleanup;
    }

    // Create a string reference JSON item
    json_string_ref = cJSON_CreateStringReference(str);
    if (!json_string_ref) {
        goto cleanup;
    }

    // Create an object JSON item
    json_object = cJSON_CreateObject();
    if (!json_object) {
        goto cleanup;
    }

    // Create an object reference JSON item
    json_object_ref = cJSON_CreateObjectReference(json_object);
    if (!json_object_ref) {
        goto cleanup;
    }

    // Cleanup all allocated resources
cleanup:
    if (json_bool) cJSON_Delete(json_bool);
    if (json_string) cJSON_Delete(json_string);
    if (json_array_ref) cJSON_Delete(json_array_ref);
    if (json_string_ref) cJSON_Delete(json_string_ref);
    if (json_object) cJSON_Delete(json_object);
    if (json_object_ref) cJSON_Delete(json_object_ref);

    return 0;
}
