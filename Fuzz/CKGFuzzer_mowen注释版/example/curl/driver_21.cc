#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely reallocate memory
void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(ptr);
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

// Function to safely duplicate a string
char* safe_strdup(const char* str) {
    char* new_str = strdup(str);
    if (!new_str) {
        fprintf(stderr, "String duplication failed\n");
        exit(EXIT_FAILURE);
    }
    return new_str;
}

// Function to safely calloc memory
void* safe_calloc(size_t nmemb, size_t size) {
    void* ptr = calloc(nmemb, size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    free(ptr);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < sizeof(long) + 1) {
        return 0;
    }

    // Extract the flags from the input data
    long flags = *reinterpret_cast<const long*>(data);
    data += sizeof(long);
    size -= sizeof(long);

    // Extract the trace configuration string from the input data
    size_t trace_config_size = size > 256 ? 256 : size; // Limit the size to prevent excessive memory usage
    char* trace_config = static_cast<char*>(safe_malloc(trace_config_size + 1));
    memcpy(trace_config, data, trace_config_size);
    trace_config[trace_config_size] = '\0'; // Null-terminate the string

    // Initialize libcurl with custom memory management
    CURLcode init_result = curl_global_init_mem(flags, safe_malloc, safe_free, safe_realloc, safe_strdup, safe_calloc);
    if (init_result != CURLE_OK) {
        safe_free(trace_config);
        return 0;
    }

    // Set global trace configuration
    CURLcode trace_result = curl_global_trace(trace_config);
    if (trace_result != CURLE_OK) {
        curl_global_cleanup();
        safe_free(trace_config);
        return 0;
    }

    // Set global SSL settings
    const curl_ssl_backend** available_backends;
    CURLsslset sslset_result = curl_global_sslset(CURLSSLBACKEND_NONE, nullptr, &available_backends);
    if (sslset_result != CURLSSLSET_OK) {
        curl_global_cleanup();
        safe_free(trace_config);
        return 0;
    }

    // Clean up global resources
    curl_global_cleanup();

    // Free allocated memory
    safe_free(trace_config);

    return 0;
}
