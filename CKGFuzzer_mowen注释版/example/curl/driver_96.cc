#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory and copy data
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = static_cast<char*>(malloc(size + 1));
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory and copy data
char* safe_strdup(const char* str) {
    if (!str) return nullptr;
    size_t len = strlen(str);
    char* new_str = static_cast<char*>(malloc(len + 1));
    if (!new_str) return nullptr;
    memcpy(new_str, str, len + 1);
    return new_str;
}

// Function to safely free allocated memory
void safe_free(void* ptr) {
    if (ptr) free(ptr);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty
    if (size == 0) return 0;

    // Initialize curl
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

    // Create an easy handle
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

    // Create a MIME part for data
    curl_mimepart* mime_part = curl_mime_addpart(mime);
    if (!mime_part) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Create a URL handle
    CURLU* url_handle = curl_url();
    if (!url_handle) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Safely allocate memory for the data
    char* data_str = safe_strndup(data, size);
    if (!data_str) {
        curl_url_cleanup(url_handle);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set MIME data
    CURLcode mime_data_res = curl_mime_data(mime_part, data_str, size);
    if (mime_data_res != CURLE_OK) {
        safe_free(data_str);
        curl_url_cleanup(url_handle);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set MIME headers
    CURLcode mime_headers_res = curl_mime_headers(mime_part, nullptr, 0);
    if (mime_headers_res != CURLE_OK) {
        safe_free(data_str);
        curl_url_cleanup(url_handle);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Get URL part
    char* url_part = nullptr;
    CURLUcode url_get_res = curl_url_get(url_handle, CURLUPART_HOST, &url_part, 0);
    if (url_get_res != CURLUE_OK) {
        safe_free(data_str);
        curl_url_cleanup(url_handle);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Remove easy handle from multi handle
    CURLMcode remove_handle_res = curl_multi_remove_handle(multi_handle, easy_handle);
    if (remove_handle_res != CURLM_OK) {
        safe_free(data_str);
        safe_free(url_part);
        curl_url_cleanup(url_handle);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Clean up
    safe_free(data_str);
    safe_free(url_part);
    curl_url_cleanup(url_handle);
    curl_mime_free(mime);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
