#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h> // Add this include for 'false'

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a cJSON string from fuzz input
cJSON* create_cjson_string(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return NULL;
    cJSON* item = cJSON_CreateString(str);
    free(str);
    return item;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 2) return 0;

    // Create a JSON object
    cJSON* root = cJSON_CreateObject();
    if (!root) return 0;

    // Create a string item from the fuzz input
    cJSON* string_item = create_cjson_string(data, size / 2);
    if (!string_item) {
        cJSON_Delete(root);
        return 0;
    }

    // Add the string item to the JSON object
    if (!cJSON_AddItemToObjectCS(root, "key", string_item)) {
        cJSON_Delete(root);
        return 0;
    }

    // Parse a JSON string from the remaining fuzz input
    const char* parse_end = NULL;
    cJSON* parsed_json = cJSON_ParseWithLengthOpts((const char*)data + size / 2, size - size / 2, &parse_end, false);
    if (!parsed_json) {
        cJSON_Delete(root);
        return 0;
    }

    // Add the parsed JSON to the root object
    if (!cJSON_AddItemToObjectCS(root, "parsed", parsed_json)) {
        cJSON_Delete(root);
        return 0;
    }

    // Print the JSON object unformatted
    char* json_str = cJSON_PrintUnformatted(root);
    if (json_str) {
        free(json_str);
    }

    // Clean up
    cJSON_Delete(root);

    return 0;
}
