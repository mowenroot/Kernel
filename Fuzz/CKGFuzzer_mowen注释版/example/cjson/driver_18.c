#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a double
double safe_atof(const uint8_t *data, size_t size) {
    char buffer[32]; // Assuming a reasonable size for a double string representation
    size_t len = size < sizeof(buffer) - 1 ? size : sizeof(buffer) - 1;
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    return atof(buffer);
}

// Function to safely convert fuzz input to a string
char* safe_strndup(const uint8_t *data, size_t size) {
    size_t len = size < SIZE_MAX - 1 ? size : SIZE_MAX - 1;
    char *str = (char*)malloc(len + 1);
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cJSON *json_number = NULL;
    cJSON *json_string = NULL;
    cJSON *parsed_json = NULL;
    char *json_str = NULL;
    char *json_string_str = NULL;
    char *parsed_json_str = NULL;

    // Create a cJSON number from the fuzz input
    double number = safe_atof(data, size);
    json_number = cJSON_CreateNumber(number);
    if (!json_number) {
        goto cleanup;
    }

    // Check if the created item is a number
    if (!cJSON_IsNumber(json_number)) {
        goto cleanup;
    }

    // Print the JSON number to a string
    json_str = cJSON_Print(json_number);
    if (!json_str) {
        goto cleanup;
    }

    // Create a cJSON string from the fuzz input
    char *str = safe_strndup(data, size);
    if (!str) {
        goto cleanup;
    }
    json_string = cJSON_CreateString(str);
    free(str);
    if (!json_string) {
        goto cleanup;
    }

    // Check if the created item is a string
    if (!cJSON_IsString(json_string)) {
        goto cleanup;
    }

    // Print the JSON string to a string
    json_string_str = cJSON_Print(json_string);
    if (!json_string_str) {
        goto cleanup;
    }

    // Parse the JSON string back into a cJSON object
    parsed_json = cJSON_Parse(json_string_str);
    if (!parsed_json) {
        goto cleanup;
    }

    // Print the parsed JSON object to a string
    parsed_json_str = cJSON_Print(parsed_json);
    if (!parsed_json_str) {
        goto cleanup;
    }

cleanup:
    // Free all allocated resources
    if (json_number) {
        cJSON_Delete(json_number);
    }
    if (json_string) {
        cJSON_Delete(json_string);
    }
    if (parsed_json) {
        cJSON_Delete(parsed_json);
    }
    if (json_str) {
        free(json_str);
    }
    if (json_string_str) {
        free(json_string_str);
    }
    if (parsed_json_str) {
        free(parsed_json_str);
    }

    return 0;
}
