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
    // Initialize variables
    CURLM* multi_handle = nullptr;
    CURL* easy_handle = nullptr;
    CURLMcode mcode;
    CURLcode code;

    // Initialize the multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0; // Failed to initialize multi handle
    }

    // Initialize the easy handle
    easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0; // Failed to initialize easy handle
    }

    // Set options for the easy handle using fuzz input
    const size_t option_size = size / 2;
    const size_t value_size = size - option_size;
    long option = safe_strtol(data, option_size);
    char* value = safe_strndup(data + option_size, value_size);

    if (value) {
        code = curl_easy_setopt(easy_handle, static_cast<CURLoption>(option), value);
        free(value);
        if (code != CURLE_OK) {
            curl_easy_cleanup(easy_handle);
            curl_multi_cleanup(multi_handle);
            return 0; // Failed to set option
        }
    }

    // Add the easy handle to the multi handle
    mcode = curl_multi_add_handle(multi_handle, easy_handle);
    if (mcode != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0; // Failed to add handle
    }

    // Remove the easy handle from the multi handle
    mcode = curl_multi_remove_handle(multi_handle, easy_handle);
    if (mcode != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0; // Failed to remove handle
    }

    // Cleanup
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0; // Success
}
