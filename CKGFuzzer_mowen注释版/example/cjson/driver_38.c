#include "cJSON.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include this header to declare stderr

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
        free(ptr);
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
    cJSON* new_obj = cJSON_CreateObject();
    if (new_obj == NULL) {
        cJSON_Delete(json);
        free(input_str);
        return 0;
    }

    // Replace an item in the array (if the JSON is an array)
    if (json->type == cJSON_Array) {
        cJSON_ReplaceItemInArray(json, 0, new_obj);
    }

    // Print the JSON object to a preallocated buffer
    const int buffer_size = 1024;
    char* buffer = (char*)safe_malloc(buffer_size);
    if (!cJSON_PrintPreallocated(json, buffer, buffer_size, cJSON_True)) {
        cJSON_Delete(json);
        cJSON_Delete(new_obj);
        free(input_str);
        free(buffer);
        return 0;
    }

    // Print the JSON object using cJSON_Print
    char* json_str = cJSON_Print(json);
    if (json_str == NULL) {
        cJSON_Delete(json);
        cJSON_Delete(new_obj);
        free(input_str);
        free(buffer);
        return 0;
    }

    // Print the JSON object using cJSON_PrintBuffered
    const int prebuffer_size = 1024;
    char* buffered_str = cJSON_PrintBuffered(json, prebuffer_size, cJSON_True);
    if (buffered_str == NULL) {
        cJSON_Delete(json);
        cJSON_Delete(new_obj);
        free(input_str);
        free(buffer);
        free(json_str);
        return 0;
    }

    // Clean up
    cJSON_Delete(json);
    cJSON_Delete(new_obj);
    free(input_str);
    free(buffer);
    free(json_str);
    free(buffered_str);

    return 0;
}
