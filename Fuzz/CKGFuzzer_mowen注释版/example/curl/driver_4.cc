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
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    long val = strtol(str, nullptr, 10);
    free(str);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 10) return 0;

    // Initialize cURL easy handle
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Set options using fuzz input
    const char* url = safe_strndup(data, size / 2);
    if (url) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        free((void*)url);
    }

    long timeout = safe_atol(data + size / 2, size / 2);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // Handle error (e.g., log or ignore)
    }

    // Reset the handle to its initial state
    curl_easy_reset(curl);

    // Cleanup
    curl_easy_cleanup(curl);

    return 0;
}
