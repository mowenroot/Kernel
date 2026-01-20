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

// Function to safely convert fuzz input to an integer
int safe_atoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 4) return 0;

    // Initialize CURL easy handle
    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) return 0;

    // Initialize CURL multi handle
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Initialize CURL share handle
    CURLSH* share_handle = curl_share_init();
    if (!share_handle) {
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Set options for easy handle using fuzz input
    const char* url = safe_strndup(data, size / 2);
    if (url) {
        curl_easy_setopt(easy_handle, CURLOPT_URL, url);
        free((void*)url);
    }

    // Set share handle for easy handle
    curl_easy_setopt(easy_handle, CURLOPT_SHARE, share_handle);

    // Perform multi socket operation
    int running_handles;
    CURLMcode mcode = curl_multi_socket_all(multi_handle, &running_handles);
    if (mcode != CURLM_OK) {
        curl_share_cleanup(share_handle);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Cleanup resources
    curl_share_cleanup(share_handle);
    curl_multi_cleanup(multi_handle);
    curl_easy_cleanup(easy_handle);

    return 0;
}
