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

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < sizeof(CURLMcode) + sizeof(CURLcode) + sizeof(int)) {
        return 0;
    }

    // Initialize CURL multi and easy handles
    CURLM* multi_handle = curl_multi_init();
    CURL* easy_handle = curl_easy_init();

    if (!multi_handle || !easy_handle) {
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Extract data for API calls
    CURLMcode mcode;
    CURLcode ecode;
    int running_handles;

    // Add easy handle to multi handle
    mcode = curl_multi_add_handle(multi_handle, easy_handle);
    if (mcode != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Perform multi operations
    mcode = curl_multi_perform(multi_handle, &running_handles);
    if (mcode != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Remove easy handle from multi handle
    mcode = curl_multi_remove_handle(multi_handle, easy_handle);
    if (mcode != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Cleanup easy handle
    curl_easy_cleanup(easy_handle);

    // Cleanup multi handle
    curl_multi_cleanup(multi_handle);

    return 0;
}
