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
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize CURL handles
    CURL* easy_handle = curl_easy_init();
    CURLM* multi_handle = curl_multi_init();

    if (!easy_handle || !multi_handle) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Allocate buffers for send and receive operations
    void* send_buffer = safe_malloc(size);
    void* recv_buffer = safe_malloc(size);
    size_t bytes_sent = 0;
    size_t bytes_received = 0;

    // Copy fuzz input to send buffer
    safe_memcpy(send_buffer, data, size);

    // Perform curl_easy_send operation
    CURLcode send_result = curl_easy_send(easy_handle, send_buffer, size, &bytes_sent);
    if (send_result != CURLE_OK) {
        fprintf(stderr, "curl_easy_send failed: %d\n", send_result);
    }

    // Perform curl_easy_recv operation
    CURLcode recv_result = curl_easy_recv(easy_handle, recv_buffer, size, &bytes_received);
    if (recv_result != CURLE_OK) {
        fprintf(stderr, "curl_easy_recv failed: %d\n", recv_result);
    }

    // Perform curl_ws_send operation (stub)
    size_t ws_sent = 0;
    CURLcode ws_send_result = curl_ws_send(easy_handle, send_buffer, size, &ws_sent, 0, 0);
    if (ws_send_result != CURLE_NOT_BUILT_IN) {
        fprintf(stderr, "curl_ws_send failed: %d\n", ws_send_result);
    }

    // Perform curl_ws_recv operation (stub)
    size_t ws_received = 0;
    const struct curl_ws_frame* ws_meta = nullptr;
    CURLcode ws_recv_result = curl_ws_recv(easy_handle, recv_buffer, size, &ws_received, &ws_meta);
    if (ws_recv_result != CURLE_NOT_BUILT_IN) {
        fprintf(stderr, "curl_ws_recv failed: %d\n", ws_recv_result);
    }

    // Perform curl_multi_poll operation
    struct curl_waitfd extra_fds[1];
    int ret = 0;
    CURLMcode multi_poll_result = curl_multi_poll(multi_handle, extra_fds, 0, 1000, &ret);
    if (multi_poll_result != CURLM_OK) {
        fprintf(stderr, "curl_multi_poll failed: %d\n", multi_poll_result);
    }

    // Perform curl_multi_socket_action operation
    int running_handles = 0;
    CURLMcode multi_socket_result = curl_multi_socket_action(multi_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
    if (multi_socket_result != CURLM_OK) {
        fprintf(stderr, "curl_multi_socket_action failed: %d\n", multi_socket_result);
    }

    // Clean up resources
    safe_free(send_buffer);
    safe_free(recv_buffer);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
