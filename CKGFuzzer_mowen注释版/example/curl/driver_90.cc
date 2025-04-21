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

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size < 1 || size > 1024) return 0;

    // Initialize variables
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

    curl_mime* mime = curl_mime_init(multi_handle);
    if (!mime) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Create a MIME part
    curl_mimepart* mime_part = curl_mime_addpart(mime);
    if (!mime_part) {
        curl_mime_free(mime);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set MIME data
    char* mime_data = safe_strndup(data, size); // Changed from const char* to char*
    if (mime_data) {
        CURLcode res = curl_mime_data(mime_part, mime_data, size);
        if (res != CURLE_OK) {
            free(mime_data); // Corrected to free(mime_data)
            curl_mime_free(mime);
            curl_multi_cleanup(multi_handle);
            return 0;
        }
        free(mime_data); // Corrected to free(mime_data)
    }

    // Set MIME headers
    struct curl_slist* headers = NULL;
    CURLcode res = curl_mime_headers(mime_part, headers, 1);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Prepare for multi-socket operation
    curl_socket_t socket = 0; // Dummy socket value
    int running_handles = 0;
    CURLMcode mres = curl_multi_socket(multi_handle, socket, &running_handles);
    if (mres != CURLM_OK) {
        curl_mime_free(mime);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Prepare for multi-wait operation
    struct curl_waitfd* waitfds = safe_array_malloc<struct curl_waitfd>(1);
    if (!waitfds) {
        curl_mime_free(mime);
        curl_multi_cleanup(multi_handle);
        return 0;
    }
    unsigned int fd_count = 0;
    mres = curl_multi_waitfds(multi_handle, waitfds, 1, &fd_count);
    if (mres != CURLM_OK) {
        free(waitfds);
        curl_mime_free(mime);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Clean up
    free(waitfds);
    curl_mime_free(mime);
    curl_multi_cleanup(multi_handle);

    return 0;
}
