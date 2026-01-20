#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to an integer
int safe_strntoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Derive inputs from fuzz data
    const char* url = safe_strndup(data, size / 2);
    int timeout_ms = safe_strntoi(data + size / 2, size / 2);

    // Set up easy handle
    if (url) {
        curl_easy_setopt(easy_handle, CURLOPT_URL, url);
        free((void*)url);
    }

    // Add easy handle to multi handle
    CURLMcode add_result = curl_multi_add_handle(multi_handle, easy_handle);
    if (add_result != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Perform multi operations
    int still_running = 0;
    curl_multi_perform(multi_handle, &still_running);

    // Check for messages
    int msgs_in_queue;
    CURLMsg* msg = curl_multi_info_read(multi_handle, &msgs_in_queue);
    if (msg && msg->msg == CURLMSG_DONE) {
        // Handle completed message
    }

    // Set file descriptors
    fd_set read_fd_set, write_fd_set, exc_fd_set;
    int max_fd;
    FD_ZERO(&read_fd_set);
    FD_ZERO(&write_fd_set);
    FD_ZERO(&exc_fd_set);
    CURLMcode fdset_result = curl_multi_fdset(multi_handle, &read_fd_set, &write_fd_set, &exc_fd_set, &max_fd);
    if (fdset_result != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Get timeout
    long timeout;
    CURLMcode timeout_result = curl_multi_timeout(multi_handle, &timeout);
    if (timeout_result != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Wait for activity
    int ret;
    CURLMcode wait_result = curl_multi_wait(multi_handle, NULL, 0, timeout_ms, &ret);
    if (wait_result != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Remove easy handle from multi handle
    CURLMcode remove_result = curl_multi_remove_handle(multi_handle, easy_handle);
    if (remove_result != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Cleanup
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
