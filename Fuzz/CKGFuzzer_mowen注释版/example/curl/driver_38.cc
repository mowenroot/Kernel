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

// Function to safely create a CURL easy handle
CURL* safe_curl_easy_init() {
    CURL* handle = curl_easy_init();
    if (!handle) {
        fprintf(stderr, "Failed to initialize CURL easy handle\n");
        exit(EXIT_FAILURE);
    }
    return handle;
}

// Function to safely create a CURL multi handle
CURLM* safe_curl_multi_init() {
    CURLM* handle = curl_multi_init();
    if (!handle) {
        fprintf(stderr, "Failed to initialize CURL multi handle\n");
        exit(EXIT_FAILURE);
    }
    return handle;
}

// Function to safely create a CURL mime handle
curl_mime* safe_curl_mime_init(CURL* easy) {
    curl_mime* mime = curl_mime_init(easy);
    if (!mime) {
        fprintf(stderr, "Failed to initialize CURL mime handle\n");
        exit(EXIT_FAILURE);
    }
    return mime;
}

// Function to safely create a CURL mime part
curl_mimepart* safe_curl_mime_addpart(curl_mime* mime) {
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        fprintf(stderr, "Failed to add part to CURL mime handle\n");
        exit(EXIT_FAILURE);
    }
    return part;
}

// Function to safely create a CURL slist
struct curl_slist* safe_curl_slist_append(struct curl_slist* list, const char* data) {
    struct curl_slist* new_list = curl_slist_append(list, data);
    if (!new_list) {
        fprintf(stderr, "Failed to append to CURL slist\n");
        exit(EXIT_FAILURE);
    }
    return new_list;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < 1 || size > 1024) {
        return 0;
    }

    // Initialize CURL easy and multi handles
    CURL* easy_handle = safe_curl_easy_init();
    CURLM* multi_handle = safe_curl_multi_init();

    // Initialize CURL mime handle
    curl_mime* mime = safe_curl_mime_init(easy_handle);
    curl_mimepart* part = safe_curl_mime_addpart(mime);

    // Create a CURL slist from the fuzz input
    struct curl_slist* headers = NULL;
    char* header_data = (char*)safe_malloc(size + 1);
    safe_memcpy(header_data, data, size);
    header_data[size] = '\0';
    headers = safe_curl_slist_append(headers, header_data);

    // Set MIME headers
    CURLcode mime_result = curl_mime_headers(part, headers, 1);
    if (mime_result != CURLE_OK) {
        fprintf(stderr, "Failed to set MIME headers: %d\n", mime_result);
    }

    // Add easy handle to multi handle
    CURLMcode add_result = curl_multi_add_handle(multi_handle, easy_handle);
    if (add_result != CURLM_OK) {
        fprintf(stderr, "Failed to add easy handle to multi handle: %d\n", add_result);
    }

    // Remove easy handle from multi handle
    CURLMcode remove_result = curl_multi_remove_handle(multi_handle, easy_handle);
    if (remove_result != CURLM_OK) {
        fprintf(stderr, "Failed to remove easy handle from multi handle: %d\n", remove_result);
    }

    // Cleanup multi handle
    CURLMcode cleanup_result = curl_multi_cleanup(multi_handle);
    if (cleanup_result != CURLM_OK) {
        fprintf(stderr, "Failed to cleanup multi handle: %d\n", cleanup_result);
    }

    // Cleanup easy handle
    curl_easy_cleanup(easy_handle);

    // Cleanup MIME handle
    curl_mime_free(mime);

    // Free the header data
    safe_free(header_data);

    // Free the CURL slist
    curl_slist_free_all(headers);

    return 0;
}
