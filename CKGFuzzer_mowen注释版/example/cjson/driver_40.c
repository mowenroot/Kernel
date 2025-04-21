#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h> // Include stdbool.h for bool type

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;
    char *str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely get a substring from fuzz input
char* safe_substr(const uint8_t *data, size_t size, size_t start, size_t len) {
    if (start >= size || len == 0) return NULL;
    size_t actual_len = (start + len > size) ? (size - start) : len;
    return safe_strndup(data + start, actual_len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 10) return 0;

    // Initialize variables
    cJSON *root = NULL;
    cJSON *string_item = NULL;
    char *json_str = NULL;
    char *new_valuestring = NULL;
    const char *parse_end = NULL;
    int prebuffer = 1024; // Arbitrary prebuffer size

    // Step 1: Parse the input data as a JSON string
    char *input_str = safe_strndup(data, size);
    if (!input_str) goto cleanup;

    root = cJSON_ParseWithOpts(input_str, &parse_end, false);
    if (!root) goto cleanup;

    // Step 2: Create a new string item
    string_item = cJSON_CreateString("initial_value");
    if (!string_item) goto cleanup;

    // Step 3: Add the string item to the root object
    if (!cJSON_AddItemToObject(root, "new_string", string_item)) {
        cJSON_Delete(string_item);
        goto cleanup;
    }

    // Step 4: Set a new value string for the string item
    new_valuestring = safe_substr(data, size, 5, 10); // Arbitrary substring
    if (!new_valuestring) goto cleanup;

    if (!cJSON_SetValuestring(string_item, new_valuestring)) {
        free(new_valuestring);
        goto cleanup;
    }
    free(new_valuestring);

    // Step 5: Print the JSON object to a buffered string
    json_str = cJSON_PrintBuffered(root, prebuffer, true);
    if (!json_str) goto cleanup;

    // Step 6: Clean up and free resources
    free(json_str);

cleanup:
    if (root) cJSON_Delete(root);
    if (input_str) free(input_str);

    return 0;
}
