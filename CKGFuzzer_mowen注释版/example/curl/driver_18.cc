#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

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

// Function to safely allocate zeroed memory
void* safe_calloc(size_t nmemb, size_t size) {
    void* ptr = calloc(nmemb, size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation (calloc) failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < sizeof(CURLcode) + sizeof(CURLSHcode) + sizeof(long) + sizeof(CURLUcode)) {
        return 0;
    }

    // Extract values from the fuzz input
    CURLcode curl_error = static_cast<CURLcode>(data[0]);
    CURLSHcode share_error = static_cast<CURLSHcode>(data[1]);
    long flags = static_cast<long>(data[2]);
    CURLUcode url_error = static_cast<CURLUcode>(data[3]);

    // Initialize libcurl with custom memory functions
    CURLcode init_result = curl_global_init_mem(flags, safe_malloc, free, safe_realloc, safe_strdup, safe_calloc);
    if (init_result != CURLE_OK) {
        fprintf(stderr, "curl_global_init_mem failed: %s\n", curl_easy_strerror(init_result));
        return 0;
    }

    // Use curl_easy_strerror
    const char* easy_error_str = curl_easy_strerror(curl_error);
    if (easy_error_str) {
        fprintf(stderr, "curl_easy_strerror: %s\n", easy_error_str);
    }

    // Use curl_share_strerror
    const char* share_error_str = curl_share_strerror(share_error);
    if (share_error_str) {
        fprintf(stderr, "curl_share_strerror: %s\n", share_error_str);
    }

    // Use curl_url_strerror
    const char* url_error_str = curl_url_strerror(url_error);
    if (url_error_str) {
        fprintf(stderr, "curl_url_strerror: %s\n", url_error_str);
    }

    // Cleanup libcurl global state
    curl_global_cleanup();

    return 0;
}
