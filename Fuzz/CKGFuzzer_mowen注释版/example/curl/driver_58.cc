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
    // Ensure we have enough data for the operations
    if (size < 8) return 0;

    // Initialize libcurl global state
    long flags = safe_atol(data, 4);
    CURLcode global_init_result = curl_global_init(flags);
    if (global_init_result != CURLE_OK) {
        return 0; // Early exit if global init fails
    }

    // Initialize a CURL easy handle
    CURL* curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return 0; // Early exit if handle init fails
    }

    // Perform some operations with the handle (dummy operations for fuzzing)
    // For example, set a dummy URL (not actually used in this fuzzer)
    char* url = safe_strndup(data + 4, size - 4);
    if (url) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        free(url);
    }

    // Retrieve version information
    curl_version_info_data* version_info = curl_version_info(CURLVERSION_NOW);
    if (version_info) {
        // Dummy check to ensure version info is not null
        (void)version_info->age;
    }

    // Cleanup the CURL easy handle
    curl_easy_cleanup(curl);

    // Cleanup global libcurl state
    curl_global_cleanup();

    return 0; // Return 0 to indicate success
}
