#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to a long
long safe_atol(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    long val = strtol(str, nullptr, 10);
    free(str);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough input to proceed
    if (size < 4) return 0;

    // Initialize libcurl globally
    CURLcode global_init_result = curl_global_init(safe_atol(data, 4));
    if (global_init_result != CURLE_OK) {
        return 0;
    }

    // Initialize an easy handle
    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Get version information
    const char* version_str = curl_version();
    if (!version_str) {
        curl_easy_cleanup(easy_handle);
        curl_global_cleanup();
        return 0;
    }

    // Get detailed version information
    curl_version_info_data* version_info = curl_version_info(CURLVERSION_NOW);
    if (!version_info) {
        curl_easy_cleanup(easy_handle);
        curl_global_cleanup();
        return 0;
    }

    // Cleanup resources
    curl_easy_cleanup(easy_handle);
    curl_global_cleanup();

    return 0;
}
