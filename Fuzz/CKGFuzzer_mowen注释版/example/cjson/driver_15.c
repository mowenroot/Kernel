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

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize hooks to default memory management
    cJSON_Hooks hooks = {0};
    cJSON_InitHooks(&hooks);

    // Safely duplicate the input data to a null-terminated string
    char *json_str = safe_strndup(data, size);
    if (json_str == NULL) return 0;

    // Parse the JSON string with default options
    cJSON *parsed_json = cJSON_Parse(json_str);
    if (parsed_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            // Handle error by logging or other means
        }
        free(json_str);
        return 0;
    }

    // Attempt to parse the JSON string with length and options
    const char *parse_end = NULL;
    cJSON *parsed_with_opts = cJSON_ParseWithLengthOpts(json_str, size, &parse_end, cJSON_False);
    if (parsed_with_opts == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            // Handle error by logging or other means
        }
        cJSON_Delete(parsed_json);
        free(json_str);
        return 0;
    }

    // Retrieve an object item case-sensitive
    const char *key = "example_key";
    cJSON *item = cJSON_GetObjectItemCaseSensitive(parsed_json, key);
    if (item == NULL) {
        // Handle error by logging or other means
    }

    // Clean up resources
    cJSON_Delete(parsed_json);
    cJSON_Delete(parsed_with_opts);
    free(json_str);

    return 0;
}
