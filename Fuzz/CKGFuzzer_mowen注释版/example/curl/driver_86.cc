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

// Function to safely allocate and copy a string from fuzz input
char* safe_strdup(const char* str) {
    if (!str) return nullptr;
    size_t len = strlen(str);
    char* new_str = (char*)malloc(len + 1);
    if (!new_str) return nullptr;
    memcpy(new_str, str, len + 1);
    return new_str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize libcurl
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Safely extract strings from fuzz input
    char* url = safe_strndup(data, size);
    if (!url) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set options for the easy handle
    CURLcode res = curl_easy_setopt(easy_handle, CURLOPT_URL, url);
    if (res != CURLE_OK) {
        free(url);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Add the easy handle to the multi handle
    CURLMcode mres = curl_multi_add_handle(multi_handle, easy_handle); // Changed res to mres
    if (mres != CURLM_OK) {
        free(url);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Perform a multi perform to start the transfer
    int still_running;
    mres = curl_multi_perform(multi_handle, &still_running); // Changed res to mres
    if (mres != CURLM_OK) {
        free(url);
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Get information from the easy handle
    char* effective_url;
    res = curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &effective_url);
    if (res != CURLE_OK) {
        free(url);
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Clean up
    free(url);
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
