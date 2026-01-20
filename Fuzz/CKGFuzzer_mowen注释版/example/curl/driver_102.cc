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

// Function to safely get a substring from fuzz input
char* safe_substr(const uint8_t* data, size_t size, size_t start, size_t length) {
    if (start >= size || length == 0) return NULL;
    size_t actual_length = (start + length > size) ? (size - start) : length;
    return safe_strndup(data + start, actual_length);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    CURL* easy_handle = NULL;
    curl_mime* mime_handle = NULL;
    curl_mimepart* mime_part = NULL;
    CURLU* url_handle = NULL;
    char* header_name = NULL;

    // Initialize the easy handle
    easy_handle = curl_easy_init();
    if (!easy_handle) {
        goto cleanup;
    }

    // Initialize the MIME handle
    mime_handle = curl_mime_init(easy_handle);
    if (!mime_handle) {
        goto cleanup;
    }

    // Add a part to the MIME structure
    mime_part = curl_mime_addpart(mime_handle);
    if (!mime_part) {
        goto cleanup;
    }

    // Initialize the URL handle
    url_handle = curl_url(); // Use curl_url() to initialize the URL handle
    if (!url_handle) {
        goto cleanup;
    }

    // Safely get a header name from the fuzz input
    header_name = safe_substr(data, size, 0, size / 2);
    if (!header_name) {
        goto cleanup;
    }

    // Call curl_pushheader_byname (placeholder function)
    curl_pushheader_byname(NULL, header_name);

    // Cleanup the URL handle
    curl_url_cleanup(url_handle);
    url_handle = NULL;

cleanup:
    // Free allocated resources
    if (header_name) {
        free(header_name);
    }
    if (url_handle) {
        curl_url_cleanup(url_handle); // Ensure cleanup is done using curl_url_cleanup
    }
    if (mime_handle) {
        curl_mime_free(mime_handle);
    }
    if (easy_handle) {
        curl_easy_cleanup(easy_handle);
    }

    return 0;
}
