#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 2) {
        return 0;
    }

    // Initialize variables
    cJSON *root = NULL;
    cJSON *null_item = NULL;
    cJSON *detached_item = NULL;
    cJSON *string_ref = NULL;
    cJSON *parsed_json = NULL;
    const char *parse_end = NULL;

    // Create a new cJSON object
    root = cJSON_CreateObject();
    if (root == NULL) {
        goto cleanup;
    }

    // Add a null value to the object
    char null_name[2] = { (char)data[0], '\0' }; // Use the first byte as the name
    null_item = cJSON_AddNullToObject(root, null_name);
    if (null_item == NULL) {
        goto cleanup;
    }

    // Detach the null item from the object
    detached_item = cJSON_DetachItemFromObjectCaseSensitive(root, null_name);
    if (detached_item == NULL) {
        goto cleanup;
    }

    // Create a string reference
    char string_ref_data[2] = { (char)data[1], '\0' }; // Use the second byte as the string
    string_ref = cJSON_CreateStringReference(string_ref_data);
    if (string_ref == NULL) {
        goto cleanup;
    }

    // Parse a JSON string with options
    char json_string[3] = { '{', (char)data[0], '}' }; // Construct a minimal JSON string
    parsed_json = cJSON_ParseWithOpts(json_string, &parse_end, cJSON_False);
    if (parsed_json == NULL) {
        goto cleanup;
    }

    // Cleanup
cleanup:
    if (root != NULL) {
        cJSON_Delete(root);
    }
    if (detached_item != NULL) {
        cJSON_Delete(detached_item);
    }
    if (string_ref != NULL) {
        cJSON_Delete(string_ref);
    }
    if (parsed_json != NULL) {
        cJSON_Delete(parsed_json);
    }

    return 0;
}
