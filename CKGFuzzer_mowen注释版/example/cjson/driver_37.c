#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added to include the declaration of stderr

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

// Function to safely reallocate memory and handle errors
void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (new_ptr == NULL) {
        fprintf(stderr, "Memory reallocation failed\n");
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Convert the input data to a null-terminated string
    char* input_str = (char*)safe_malloc(size + 1);
    safe_strncpy(input_str, (const char*)data, size + 1);

    // Parse the JSON input with length options
    const char* parse_end = NULL;
    cJSON* json = cJSON_ParseWithLengthOpts(input_str, size, &parse_end, cJSON_False);
    if (json == NULL) {
        free(input_str);
        return 0;
    }

    // Create a new JSON object
    cJSON* new_object = cJSON_CreateObject();
    if (new_object == NULL) {
        cJSON_Delete(json);
        free(input_str);
        return 0;
    }

    // Replace an item in the array (if the parsed JSON is an array)
    if (json->type == cJSON_Array) {
        cJSON_ReplaceItemInArray(json, 0, new_object);
    }

    // Print the JSON object to a preallocated buffer
    const int buffer_size = 1024;
    char* buffer = (char*)safe_malloc(buffer_size);
    if (!cJSON_PrintPreallocated(json, buffer, buffer_size, cJSON_True)) {
        cJSON_Delete(json);
        cJSON_Delete(new_object);
        free(input_str);
        free(buffer);
        return 0;
    }

    // Print the JSON object using cJSON_Print
    char* printed_json = cJSON_Print(json);
    if (printed_json == NULL) {
        cJSON_Delete(json);
        cJSON_Delete(new_object);
        free(input_str);
        free(buffer);
        return 0;
    }

    // Print the JSON object using cJSON_PrintBuffered
    const int prebuffer_size = 1024;
    char* buffered_json = cJSON_PrintBuffered(json, prebuffer_size, cJSON_True);
    if (buffered_json == NULL) {
        cJSON_Delete(json);
        cJSON_Delete(new_object);
        free(input_str);
        free(buffer);
        free(printed_json);
        return 0;
    }

    // Clean up allocated resources
    cJSON_Delete(json);
    cJSON_Delete(new_object);
    free(input_str);
    free(buffer);
    free(printed_json);
    free(buffered_json);

    return 0;
}
