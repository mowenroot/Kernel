#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <string> // Added include for std::string
#include <algorithm> // Added include for std::min

// Function to safely convert fuzzer input to a string
std::string SafeStringFromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0) return "";
    size_t len = std::min(size, static_cast<size_t>(1024)); // Limit to 1024 bytes
    return std::string(reinterpret_cast<const char*>(data), len);
}

// Function to safely convert fuzzer input to an integer
int SafeIntFromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    size_t len = std::min(size, static_cast<size_t>(sizeof(int)));
    int result = 0;
    memcpy(&result, data, len);
    return result;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize curl multi handle
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0;
    }

    // Initialize curl easy handle
    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set up curl easy handle with fuzzer input
    std::string url = SafeStringFromFuzzInput(data, size);
    curl_easy_setopt(easy_handle, CURLOPT_URL, url.c_str());

    // Add easy handle to multi handle
    CURLMcode add_handle_result = curl_multi_add_handle(multi_handle, easy_handle);
    if (add_handle_result != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set options for multi handle
    int timeout_ms = SafeIntFromFuzzInput(data, size);
    curl_multi_setopt(multi_handle, CURLMOPT_MAXCONNECTS, timeout_ms);

    // Poll for activity
    int numfds = 0;
    CURLMcode poll_result = curl_multi_poll(multi_handle, NULL, 0, timeout_ms, &numfds);
    if (poll_result != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Read messages from the multi handle
    int msgs_in_queue;
    CURLMsg* msg = curl_multi_info_read(multi_handle, &msgs_in_queue);
    if (msg && msg->msg == CURLMSG_DONE) {
        // Handle completed message
    }

    // Wake up the multi handle
    CURLMcode wakeup_result = curl_multi_wakeup(multi_handle);
    if (wakeup_result != CURLM_OK) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Remove easy handle from multi handle
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
