#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzzer input to a C-string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzzer input to an integer
int safe_strntoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size > 1024) return 0;

    // Initialize variables
    CURL* curl = nullptr;
    CURL* dup_curl = nullptr;
    char* escaped_url = nullptr;
    char* url = nullptr;
    int url_length = 0;
    CURLcode res;
    char* info_buffer = nullptr; // Initialize here to avoid jump bypass

    // Initialize the CURL handle
    curl = curl_easy_init();
    if (!curl) return 0;

    // Derive URL from fuzzer input
    url = safe_strndup(data, size);
    if (!url) goto cleanup;

    // Derive URL length from fuzzer input
    url_length = safe_strntoi(data, size);

    // Escape the URL
    escaped_url = curl_easy_escape(curl, url, url_length);
    if (!escaped_url) goto cleanup;

    // Duplicate the CURL handle
    dup_curl = curl_easy_duphandle(curl);
    if (!dup_curl) goto cleanup;

    // Get information from the duplicated handle
    res = curl_easy_getinfo(dup_curl, CURLINFO_EFFECTIVE_URL, &info_buffer);
    if (res != CURLE_OK) goto cleanup;

    // Cleanup
cleanup:
    if (escaped_url) curl_free(escaped_url);
    if (url) free(url);
    if (dup_curl) curl_easy_cleanup(dup_curl);
    if (curl) curl_easy_cleanup(curl);

    return 0;
}
