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
long safe_strtol(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    char* endptr;
    long val = strtol(str, &endptr, 10);
    free(str);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize cURL
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Set URL from fuzz input
    char* url = safe_strndup(data, size);
    if (url) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        free(url);
    }

    // Set timeout from fuzz input
    long timeout = safe_strtol(data, size);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // Handle error
        curl_easy_cleanup(curl);
        return 0;
    }

    // Get information from the request
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    // Reset the handle for reuse
    curl_easy_reset(curl);

    // Cleanup
    curl_easy_cleanup(curl);

    return 0;
}
