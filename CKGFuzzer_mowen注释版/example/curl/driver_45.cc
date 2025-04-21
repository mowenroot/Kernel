#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely allocate memory and handle errors
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
template <typename T>
void safe_free(T* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data with bounds checking
void safe_copy(void* dest, const void* src, size_t size) {
    if (src && dest && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely cast data with bounds checking
template <typename T>
T safe_cast(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(T) <= size) {
        return *reinterpret_cast<const T*>(data + offset);
    }
    return T();
}

// Function to safely get a string from fuzz input
char* safe_get_string(const uint8_t* data, size_t size, size_t offset, size_t max_len) {
    if (offset + max_len <= size) {
        char* str = safe_malloc<char>(max_len + 1);
        safe_copy(str, data + offset, max_len);
        str[max_len] = '\0';
        return str;
    }
    return nullptr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    CURLM* multi_handle = curl_multi_init();
    CURL* easy_handle = curl_easy_init();
    CURLU* url_handle = curl_url();
    curl_mime* mime_handle = curl_mime_init(easy_handle);
    curl_mimepart* mime_part = curl_mime_addpart(mime_handle);

    // Ensure proper initialization
    if (!multi_handle || !easy_handle || !url_handle || !mime_handle || !mime_part) {
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        curl_url_cleanup(url_handle);
        curl_mime_free(mime_handle);
        return 0;
    }

    // Extract data from fuzz input
    size_t offset = 0;
    char* url_str = safe_get_string(data, size, offset, 256);
    offset += 256;
    char* user_str = safe_get_string(data, size, offset, 64);
    offset += 64;
    char* password_str = safe_get_string(data, size, offset, 64);
    offset += 64;
    char* host_str = safe_get_string(data, size, offset, 256);
    offset += 256;
    char* path_str = safe_get_string(data, size, offset, 256);
    offset += 256;
    char* query_str = safe_get_string(data, size, offset, 256);
    offset += 256;
    char* fragment_str = safe_get_string(data, size, offset, 256);
    offset += 256;

    // Set URL parts
    if (url_str) {
        curl_url_set(url_handle, CURLUPART_URL, url_str, 0);
    }
    if (user_str) {
        curl_url_set(url_handle, CURLUPART_USER, user_str, 0);
    }
    if (password_str) {
        curl_url_set(url_handle, CURLUPART_PASSWORD, password_str, 0);
    }
    if (host_str) {
        curl_url_set(url_handle, CURLUPART_HOST, host_str, 0);
    }
    if (path_str) {
        curl_url_set(url_handle, CURLUPART_PATH, path_str, 0);
    }
    if (query_str) {
        curl_url_set(url_handle, CURLUPART_QUERY, query_str, 0);
    }
    if (fragment_str) {
        curl_url_set(url_handle, CURLUPART_FRAGMENT, fragment_str, 0);
    }

    // Get URL parts
    char* scheme;
    char* user;
    char* password;
    char* host;
    char* path;
    char* query;
    char* fragment;

    curl_url_get(url_handle, CURLUPART_SCHEME, &scheme, 0);
    curl_url_get(url_handle, CURLUPART_USER, &user, 0);
    curl_url_get(url_handle, CURLUPART_PASSWORD, &password, 0);
    curl_url_get(url_handle, CURLUPART_HOST, &host, 0);
    curl_url_get(url_handle, CURLUPART_PATH, &path, 0);
    curl_url_get(url_handle, CURLUPART_QUERY, &query, 0);
    curl_url_get(url_handle, CURLUPART_FRAGMENT, &fragment, 0);

    // Clean up URL parts
    curl_free(scheme);
    curl_free(user);
    curl_free(password);
    curl_free(host);
    curl_free(path);
    curl_free(query);
    curl_free(fragment);

    // Set MIME data callback
    curl_mime_data_cb(mime_part, 0, nullptr, nullptr, nullptr, nullptr);

    // Add MIME subparts
    curl_mime_subparts(mime_part, mime_handle);

    // Remove easy handle from multi handle
    CURLMcode remove_result = curl_multi_remove_handle(multi_handle, easy_handle);
    if (remove_result != CURLM_OK) {
        fprintf(stderr, "curl_multi_remove_handle failed: %d\n", remove_result);
    }

    // Clean up resources
    curl_multi_cleanup(multi_handle);
    curl_easy_cleanup(easy_handle);
    curl_url_cleanup(url_handle);
    curl_mime_free(mime_handle);

    // Free allocated strings
    safe_free(url_str);
    safe_free(user_str);
    safe_free(password_str);
    safe_free(host_str);
    safe_free(path_str);
    safe_free(query_str);
    safe_free(fragment_str);

    return 0;
}
