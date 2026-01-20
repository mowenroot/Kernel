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

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size < 1 || size > 1024) {
        return 0;
    }

    // Initialize libcurl
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Create a MIME part
    curl_mime* mime = curl_mime_init(easy_handle);
    if (!mime) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    curl_mimepart* mime_part = curl_mime_addpart(mime);
    if (!mime_part) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Derive API inputs from fuzz driver inputs
    curl_socket_t socket = static_cast<curl_socket_t>(data[0]);
    int action = static_cast<int>(data[1]);
    const char* encoding = reinterpret_cast<const char*>(data + 2);
    size_t encoding_len = size - 2;

    // Allocate memory for headers
    struct curl_slist* headers = nullptr;
    if (size > 2) {
        headers = curl_slist_append(headers, reinterpret_cast<const char*>(data + 2));
    }

    // Call curl_multi_socket
    int running_handles;
    CURLMcode multi_result = curl_multi_socket(multi_handle, socket, &running_handles);
    if (multi_result != CURLM_OK) {
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_easy_pause
    CURLcode easy_result = curl_easy_pause(easy_handle, action);
    if (easy_result != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_mime_headers
    CURLcode mime_headers_result = curl_mime_headers(mime_part, headers, 1);
    if (mime_headers_result != CURLE_NOT_BUILT_IN) {
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_mime_encoder
    CURLcode mime_encoder_result = curl_mime_encoder(mime_part, encoding);
    if (mime_encoder_result != CURLE_NOT_BUILT_IN) {
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_mime_subparts
    CURLcode mime_subparts_result = curl_mime_subparts(mime_part, mime);
    if (mime_subparts_result != CURLE_NOT_BUILT_IN) {
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Clean up resources
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
