#include <stdio.h>  // Add this line to include the declaration for stderr
#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string with bounds checking
char* safe_strncpy(char* dest, const char* src, size_t dest_size) {
    if (dest == NULL || src == NULL || dest_size == 0) {
        return NULL;
    }
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    return dest;
}

// Function to safely allocate memory and handle errors
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Convert the fuzzer input to a null-terminated string
    char* input_str = (char*)safe_malloc(size + 1);
    safe_strncpy(input_str, (const char*)data, size + 1);

    // Initialize variables for API calls
    cJSON* parsed_json = NULL;
    char* printed_json = NULL;
    char* preallocated_buffer = NULL;
    const char* parse_end = NULL;

    // Test cJSON_Parse
    parsed_json = cJSON_Parse(input_str);
    if (parsed_json != NULL) {
        // Test cJSON_Print
        printed_json = cJSON_Print(parsed_json);
        if (printed_json != NULL) {
            free(printed_json);
        }

        // Test cJSON_PrintBuffered
        printed_json = cJSON_PrintBuffered(parsed_json, size, cJSON_False);
        if (printed_json != NULL) {
            free(printed_json);
        }

        // Test cJSON_PrintPreallocated
        preallocated_buffer = (char*)safe_malloc(size + 1);
        if (cJSON_PrintPreallocated(parsed_json, preallocated_buffer, size, cJSON_False)) {
            free(preallocated_buffer);
        } else {
            free(preallocated_buffer);
        }

        // Clean up
        cJSON_Delete(parsed_json);
    }

    // Test cJSON_ParseWithOpts
    parsed_json = cJSON_ParseWithOpts(input_str, &parse_end, cJSON_False);
    if (parsed_json != NULL) {
        cJSON_Delete(parsed_json);
    }

    // Test cJSON_ParseWithLengthOpts
    parsed_json = cJSON_ParseWithLengthOpts(input_str, size, &parse_end, cJSON_False);
    if (parsed_json != NULL) {
        cJSON_Delete(parsed_json);
    }

    // Clean up
    free(input_str);

    return 0;
}
