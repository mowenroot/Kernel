#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to a size_t value
size_t safe_size_t(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    size_t value = 0;
    for (size_t i = 0; i < size && i < sizeof(size_t); ++i) {
        value |= (size_t)data[i] << (8 * i);
    }
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    CURL* easy_handle = NULL;
    CURLM* multi_handle = NULL;
    CURLcode res;
    CURLMcode mres;
    char* url = NULL;
    size_t url_size = 0;

    // Ensure proper initialization of variables
    memset(&easy_handle, 0, sizeof(easy_handle));
    memset(&multi_handle, 0, sizeof(multi_handle));

    // Initialize the easy handle
    easy_handle = curl_easy_init();
    if (!easy_handle) {
        goto cleanup;
    }

    // Initialize the multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        goto cleanup;
    }

    // Derive URL from fuzz input
    url_size = size > 1024 ? 1024 : size; // Limit URL size to prevent excessive memory usage
    url = safe_strndup(data, url_size);
    if (!url) {
        goto cleanup;
    }

    // Set the URL option
    res = curl_easy_setopt(easy_handle, CURLOPT_URL, url);
    if (res != CURLE_OK) {
        goto cleanup;
    }

    // Add the easy handle to the multi handle
    mres = curl_multi_add_handle(multi_handle, easy_handle);
    if (mres != CURLM_OK) {
        goto cleanup;
    }

    // Remove the easy handle from the multi handle
    mres = curl_multi_remove_handle(multi_handle, easy_handle);
    if (mres != CURLM_OK) {
        goto cleanup;
    }

    // Cleanup
cleanup:
    if (url) {
        free(url);
    }
    if (easy_handle) {
        curl_easy_cleanup(easy_handle);
    }
    if (multi_handle) {
        curl_multi_cleanup(multi_handle);
    }

    return 0;
}
