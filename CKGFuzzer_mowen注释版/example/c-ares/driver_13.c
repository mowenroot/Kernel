#include "ares.h"
#include "ares_nameser.h"
#include "ares_dns.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int extract_int(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset + sizeof(int) > size) {
        return 0; // Return a default value if not enough data
    }
    int value = *(int *)(data + *offset);
    *offset += sizeof(int);
    return value;
}

// Function to safely extract a string from the fuzz input
char *extract_string(const uint8_t *data, size_t size, size_t *offset, size_t max_len) {
    if (*offset + max_len > size) {
        return NULL; // Return NULL if not enough data
    }
    char *str = (char *)malloc(max_len + 1);
    if (!str) {
        return NULL; // Return NULL if allocation fails
    }
    memcpy(str, data + *offset, max_len);
    str[max_len] = '\0';
    *offset += max_len;
    return str;
}

// Main fuzzing function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    int flags = extract_int(data, size, &offset);
    char *connectivity_manager_str = extract_string(data, size, &offset, 100); // Example max length

    // Initialize the library
    int init_result = ares_library_init(flags);
    if (init_result != ARES_SUCCESS) {
        // Handle initialization error
        free(connectivity_manager_str);
        return 0;
    }

    // Check if the library is initialized
    int is_initialized = ares_library_initialized();
    if (is_initialized != ARES_SUCCESS) {
        // Handle initialization check error
        ares_library_cleanup();
        free(connectivity_manager_str);
        return 0;
    }

    // Check thread safety
    ares_bool_t is_thread_safe = ares_threadsafety();
    if (is_thread_safe != ARES_FALSE) {
        // Handle thread safety check error
        ares_library_cleanup();
        free(connectivity_manager_str);
        return 0;
    }

    // Initialize for Android
    int android_init_result = ares_library_init_android(connectivity_manager_str);
    if (android_init_result != ARES_SUCCESS) {
        // Handle Android initialization error
        ares_library_cleanup();
        free(connectivity_manager_str);
        return 0;
    }

    // Cleanup the library
    ares_library_cleanup();

    // Free allocated resources
    free(connectivity_manager_str);

    return 0;
}
