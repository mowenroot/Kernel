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

// Function to safely copy a URL from fuzz input
char* safe_url_copy(const uint8_t* data, size_t size) {
    // Limit the URL length to prevent excessive memory usage
    size_t max_url_length = 2048;
    if (size > max_url_length) size = max_url_length;
    return safe_strndup(data, size);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize the CURL handle
    CURL* curl = curl_easy_init();
    if (!curl) {
        return 0; // Early exit if initialization fails
    }

    // Safely copy the URL from fuzz input
    char* url = safe_url_copy(data, size);
    if (!url) {
        curl_easy_cleanup(curl);
        return 0; // Early exit if URL copy fails
    }

    // Set the URL option
    CURLcode res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (res != CURLE_OK) {
        free(url);
        curl_easy_cleanup(curl);
        return 0; // Early exit if setting URL fails
    }

    // Perform the request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // Handle the error (e.g., log it)
    }

    // Clean up resources
    free(url);
    curl_easy_cleanup(curl);

    return 0; // Return 0 to indicate success
}
