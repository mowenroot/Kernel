#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a long
long safe_atol(const uint8_t *data, size_t size) {
    char *endptr;
    char *str = (char *)malloc(size + 1);
    if (!str) return 0;
    memcpy(str, data, size);
    str[size] = '\0';
    long val = strtol(str, &endptr, 10);
    free(str);
    if (endptr == str || *endptr != '\0') return 0;
    return val;
}

// Function to safely convert fuzz input to a curl_socket_t
curl_socket_t safe_atocurl_socket_t(const uint8_t *data, size_t size) {
    long val = safe_atol(data, size);
    return static_cast<curl_socket_t>(val);
}

// Function to safely convert fuzz input to an int
int safe_atoi(const uint8_t *data, size_t size) {
    long val = safe_atol(data, size);
    return static_cast<int>(val);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Need at least one byte of input

    // Initialize CURLM handle
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

    // Initialize variables
    int running_handles = 0;
    long timeout_ms = 0;
    curl_socket_t socket = safe_atocurl_socket_t(data, size / 2);
    int ev_bitmask = safe_atoi(data + size / 2, size / 2);

    // Call curl_multi_timeout
    CURLMcode timeout_result = curl_multi_timeout(multi_handle, &timeout_ms);
    if (timeout_result != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_multi_socket_action
    CURLMcode socket_action_result = curl_multi_socket_action(multi_handle, socket, ev_bitmask, &running_handles);
    if (socket_action_result != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_multi_wait
    int ret = 0;
    CURLMcode wait_result = curl_multi_wait(multi_handle, nullptr, 0, timeout_ms, &ret);
    if (wait_result != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_multi_wakeup
    CURLMcode wakeup_result = curl_multi_wakeup(multi_handle);
    if (wakeup_result != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_multi_socket_all
    CURLMcode socket_all_result = curl_multi_socket_all(multi_handle, &running_handles);
    if (socket_all_result != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Cleanup
    curl_multi_cleanup(multi_handle);
    return 0;
}
