#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a structure
template <typename T>
T* safe_malloc() {
    T* ptr = (T*)malloc(sizeof(T));
    if (!ptr) return nullptr;
    memset(ptr, 0, sizeof(T));
    return ptr;
}

// Function to safely allocate memory for an array
template <typename T>
T* safe_malloc_array(size_t count) {
    T* ptr = (T*)malloc(count * sizeof(T));
    if (!ptr) return nullptr;
    memset(ptr, 0, count * sizeof(T));
    return ptr;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within reasonable limits to prevent excessive memory usage
    if (size < 1 || size > 1024) return 0;

    // Initialize variables
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

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

    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Use curl_mime_data_cb
    CURLcode mime_result = curl_mime_data_cb(part, 0, nullptr, nullptr, nullptr, nullptr);
    if (mime_result != CURLE_NOT_BUILT_IN) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Use curl_multi_poll
    struct curl_waitfd* extra_fds = safe_malloc_array<struct curl_waitfd>(1);
    if (!extra_fds) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    int ret;
    CURLMcode poll_result = curl_multi_poll(multi_handle, extra_fds, 1, 1000, &ret);
    if (poll_result != CURLM_OK) {
        free(extra_fds);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Use curl_multi_assign
    curl_socket_t socket = 0; // Dummy socket value
    void* hashp = nullptr;
    CURLMcode assign_result = curl_multi_assign(multi_handle, socket, hashp);
    if (assign_result != CURLM_OK) {
        free(extra_fds);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Use curl_ws_meta
    const struct curl_ws_frame* ws_meta = curl_ws_meta(easy_handle);
    if (ws_meta) {
        free(extra_fds);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Use curl_pushheader_byname
    char* header_name = safe_strndup(data, size);
    if (!header_name) {
        free(extra_fds);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    struct curl_pushheaders* pushheaders = nullptr; // Dummy pushheaders value
    char* push_header = curl_pushheader_byname(pushheaders, header_name);
    if (push_header) {
        free(header_name);
        free(extra_fds);
        curl_mime_free(mime);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Clean up
    free(header_name);
    free(extra_fds);
    curl_mime_free(mime);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
