#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert a size_t to an int
int safe_size_t_to_int(size_t size) {
    if (size > INT_MAX) {
        return INT_MAX;
    }
    return static_cast<int>(size);
}

// Function to safely convert a size_t to a long
long safe_size_t_to_long(size_t size) {
    if (size > LONG_MAX) {
        return LONG_MAX;
    }
    return static_cast<long>(size);
}

// Function to safely convert a size_t to an unsigned long
unsigned long safe_size_t_to_ulong(size_t size) {
    if (size > ULONG_MAX) {
        return ULONG_MAX;
    }
    return static_cast<unsigned long>(size);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit
    if (size < sizeof(CURLMcode) * 6) {
        return 0;
    }

    // Initialize the multi handle
    CURLM *multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Initialize the easy handle
    CURL *easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Add the easy handle to the multi handle
    CURLMcode add_handle_result = curl_multi_add_handle(multi_handle, easy_handle);
    if (add_handle_result != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set options on the multi handle
    CURLMcode setopt_result = curl_multi_setopt(multi_handle, CURLMOPT_SOCKETFUNCTION, nullptr);
    if (setopt_result != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Poll for activity on the multi handle
    int numfds = 0;
    CURLMcode poll_result = curl_multi_poll(multi_handle, nullptr, 0, safe_size_t_to_int(size), &numfds);
    if (poll_result != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Get the timeout for the multi handle
    long timeout_ms = 0;
    CURLMcode timeout_result = curl_multi_timeout(multi_handle, &timeout_ms);
    if (timeout_result != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Read messages from the multi handle
    int msgs_in_queue = 0;
    CURLMsg *msg = curl_multi_info_read(multi_handle, &msgs_in_queue);
    if (msg && msg->msg == CURLMSG_DONE) {
        // Handle the message if needed
    }

    // Remove the easy handle from the multi handle
    CURLMcode remove_handle_result = curl_multi_remove_handle(multi_handle, easy_handle);
    if (remove_handle_result != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Cleanup
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
