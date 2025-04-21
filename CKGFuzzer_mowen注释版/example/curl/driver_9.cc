#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely free a CURL easy handle
void safe_curl_easy_cleanup(CURL* handle) {
    if (handle) {
        curl_easy_cleanup(handle);
    }
}

// Function to safely free a CURL multi handle
void safe_curl_multi_cleanup(CURLM* multi_handle) {
    if (multi_handle) {
        curl_multi_cleanup(multi_handle);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(CURLcode) + sizeof(CURLMcode)) {
        return 0;
    }

    // Initialize CURL easy and multi handles
    CURL* easy_handle = curl_easy_init();
    CURLM* multi_handle = curl_multi_init();

    if (!easy_handle || !multi_handle) {
        safe_curl_easy_cleanup(easy_handle);
        safe_curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Derive API inputs from fuzz driver inputs
    CURLcode easy_result = static_cast<CURLcode>(data[0]);
    CURLMcode multi_result = static_cast<CURLMcode>(data[1]);

    // Call curl_easy_reset to reset the easy handle
    curl_easy_reset(easy_handle);

    // Call curl_easy_duphandle to duplicate the easy handle
    CURL* dup_handle = curl_easy_duphandle(easy_handle);
    if (dup_handle) {
        safe_curl_easy_cleanup(dup_handle);
    }

    // Call curl_easy_upkeep to ensure the upkeep of connections
    CURLcode upkeep_result = curl_easy_upkeep(easy_handle);
    if (upkeep_result != CURLE_OK) {
        safe_curl_easy_cleanup(easy_handle);
        safe_curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Add the easy handle to the multi handle
    multi_result = curl_multi_add_handle(multi_handle, easy_handle);
    if (multi_result != CURLM_OK) {
        safe_curl_easy_cleanup(easy_handle);
        safe_curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_multi_remove_handle to remove the easy handle from the multi handle
    multi_result = curl_multi_remove_handle(multi_handle, easy_handle);
    if (multi_result != CURLM_OK) {
        safe_curl_easy_cleanup(easy_handle);
        safe_curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Call curl_easy_cleanup to clean up the easy handle
    safe_curl_easy_cleanup(easy_handle);

    // Clean up the multi handle
    safe_curl_multi_cleanup(multi_handle);

    return 0;
}
