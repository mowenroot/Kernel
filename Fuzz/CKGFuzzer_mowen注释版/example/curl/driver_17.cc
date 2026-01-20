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

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Initialize variables
    CURLcode res;
    CURLsslset sslset_res;
    const curl_ssl_backend** backends = nullptr;
    char* trace_config = nullptr;
    char* ssl_name = nullptr;
    CURL* curl = nullptr;

    // Initialize custom memory management functions
    res = curl_global_init_mem(CURL_GLOBAL_DEFAULT, safe_malloc, free, safe_realloc, safe_strdup, safe_calloc);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_global_init_mem failed: %d\n", res);
        return 0;
    }

    // Initialize global state
    res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_global_init failed: %d\n", res);
        curl_global_cleanup();
        return 0;
    }

    // Initialize global SSL settings
    sslset_res = curl_global_sslset(CURLSSLBACKEND_NONE, nullptr, &backends);
    if (sslset_res != CURLSSLSET_OK) {
        fprintf(stderr, "curl_global_sslset failed: %d\n", sslset_res);
        curl_global_cleanup();
        return 0;
    }

    // Initialize global tracing
    if (size > 0) {
        trace_config = reinterpret_cast<char*>(safe_malloc(size + 1));
        memcpy(trace_config, data, size);
        trace_config[size] = '\0';
        res = curl_global_trace(trace_config);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_global_trace failed: %d\n", res);
            free(trace_config);
            curl_global_cleanup();
            return 0;
        }
        free(trace_config);
    }

    // Create a CURL easy handle
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        curl_global_cleanup();
        return 0;
    }

    // Cleanup the CURL easy handle
    curl_easy_cleanup(curl);

    // Cleanup global resources
    curl_global_cleanup();

    return 0;
}
