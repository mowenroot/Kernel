#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a structure
template <typename T>
T* safe_malloc() {
    T* ptr = (T*)malloc(sizeof(T));
    if (!ptr) return NULL;
    memset(ptr, 0, sizeof(T));
    return ptr;
}

// Function to safely allocate memory for an array
template <typename T>
T* safe_array_malloc(size_t count) {
    T* ptr = (T*)malloc(count * sizeof(T));
    if (!ptr) return NULL;
    memset(ptr, 0, count * sizeof(T));
    return ptr;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size < 1 || size > 1024) return 0;

    // Initialize variables
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    curl_mime* mime_handle = curl_mime_init(easy_handle);
    if (!mime_handle) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Create a MIME part
    curl_mimepart* mime_part = curl_mime_addpart(mime_handle);
    if (!mime_part) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set MIME data
    CURLcode mime_data_result = curl_mime_data(mime_part, (const char*)data, size);
    if (mime_data_result != CURLE_OK) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Prepare for multi socket operation
    curl_socket_t socket = 0; // Dummy socket value
    int running_handles = 0;
    CURLMcode multi_socket_result = curl_multi_socket(multi_handle, socket, &running_handles);
    if (multi_socket_result != CURLM_OK) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Prepare for multi waitfds operation
    struct curl_waitfd* ufds = safe_array_malloc<struct curl_waitfd>(1);
    if (!ufds) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    unsigned int fd_count = 0;
    CURLMcode multi_waitfds_result = curl_multi_waitfds(multi_handle, ufds, 1, &fd_count);
    free(ufds);

    if (multi_waitfds_result != CURLM_OK) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Clean up resources
    curl_mime_free(mime_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
