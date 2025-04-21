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
    // Initialize CURL easy handle
    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) return 0;

    // Initialize CURL share handle
    CURLSH* share_handle = curl_share_init();
    if (!share_handle) {
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Set options for easy handle
    CURLcode res_easy = curl_easy_setopt(easy_handle, CURLOPT_URL, safe_strndup(data, size));
    if (res_easy != CURLE_OK) {
        curl_share_cleanup(share_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Set options for share handle
    CURLSHcode res_share = curl_share_setopt(share_handle, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
    if (res_share != CURLSHE_OK) {
        curl_share_cleanup(share_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Cleanup share handle
    res_share = curl_share_cleanup(share_handle);
    if (res_share != CURLSHE_OK) {
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Cleanup easy handle
    curl_easy_cleanup(easy_handle);

    return 0;
}
