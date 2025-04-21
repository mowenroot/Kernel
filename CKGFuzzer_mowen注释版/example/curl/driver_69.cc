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

// Function to safely extract a substring from fuzz input
char* safe_substr(const uint8_t* data, size_t size, size_t start, size_t length) {
    if (start >= size || length == 0) return NULL;
    size_t actual_length = (start + length > size) ? (size - start) : length;
    return safe_strndup(data + start, actual_length);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

    // Initialize libcurl global state
    CURLcode global_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (global_init_result != CURLE_OK) {
        return 0; // Early exit on global init failure
    }

    // Initialize a CURL easy handle
    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) {
        curl_global_cleanup();
        return 0; // Early exit on easy handle init failure
    }

    // Initialize a MIME handle
    curl_mime* mime_handle = curl_mime_init(easy_handle);
    if (!mime_handle) {
        curl_easy_cleanup(easy_handle);
        curl_global_cleanup();
        return 0; // Early exit on MIME handle init failure
    }

    // Add a part to the MIME structure
    curl_mimepart* mime_part = curl_mime_addpart(mime_handle);
    if (!mime_part) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        curl_global_cleanup();
        return 0; // Early exit on MIME part add failure
    }

    // Extract a date string from fuzz input
    char* date_str = safe_substr(data, size, 0, size / 2);
    if (!date_str) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        curl_global_cleanup();
        return 0; // Early exit on date string extraction failure
    }

    // Parse the date string
    time_t parsed_date = curl_getdate(date_str, NULL);
    free(date_str);

    // Clean up resources
    curl_mime_free(mime_handle);
    curl_easy_cleanup(easy_handle);
    curl_global_cleanup();

    return 0; // Return 0 to indicate success
}
