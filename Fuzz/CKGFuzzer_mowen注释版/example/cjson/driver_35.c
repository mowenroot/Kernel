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

// Function to safely create a cJSON string item from fuzz input
cJSON* create_string_item(const uint8_t *data, size_t size) {
    char *str = safe_strndup(data, size);
    if (str == NULL) return NULL;
    cJSON *item = cJSON_CreateString(str);
    free(str);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Initialize variables
    cJSON *root = NULL;
    cJSON *item = NULL;
    cJSON *parsed = NULL;
    char *buffer = NULL;
    const char *parse_end = NULL;
    int buffer_size = 1024;
    int result = 0;

    // Allocate buffer for printing
    buffer = (char*)malloc(buffer_size);
    if (buffer == NULL) goto cleanup;

    // Parse JSON with length options
    parsed = cJSON_ParseWithLengthOpts((const char*)data, size, &parse_end, 0); // Changed 'false' to '0'
    if (parsed == NULL) goto cleanup;

    // Create a string item from a subset of the input data
    item = create_string_item(data + size / 2, size / 4);
    if (item == NULL) goto cleanup;

    // Add the string item to the parsed JSON object
    if (cJSON_AddItemToObject(parsed, "fuzz_string", item) != NULL) {
        item = NULL; // Ownership transferred to parsed
    } else {
        cJSON_Delete(item);
        item = NULL;
        goto cleanup;
    }

    // Print the modified JSON to the preallocated buffer
    if (!cJSON_PrintPreallocated(parsed, buffer, buffer_size, 1)) { // Changed 'true' to '1'
        goto cleanup;
    }

    // Parse the printed JSON again to ensure it's valid
    cJSON *reparsed = cJSON_ParseWithOpts(buffer, NULL, 0); // Changed 'false' to '0'
    if (reparsed == NULL) goto cleanup;

    // Delete an item from the array if it exists
    cJSON *array = cJSON_GetObjectItemCaseSensitive(reparsed, "array");
    if (array && cJSON_IsArray(array)) {
        cJSON_DeleteItemFromArray(array, 0);
    }

    // Cleanup
    cJSON_Delete(reparsed);

cleanup:
    if (parsed) cJSON_Delete(parsed);
    if (item) cJSON_Delete(item);
    if (buffer) free(buffer);

    return 0;
}
