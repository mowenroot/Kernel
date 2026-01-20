#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(char *dest, const uint8_t *src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
        dest[size - 1] = '\0'; // Ensure null-termination
    } else {
        dest[0] = '\0';
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within reasonable limits to prevent excessive memory usage
    if (size > 1024) {
        size = 1024;
    }

    // Initialize variables
    CURL *easy_handle = NULL;
    CURLM *multi_handle = NULL;
    curl_mime *mime_handle = NULL;
    curl_mimepart *mime_part = NULL;
    CURLcode res;
    CURLsslset ssl_res;
    const curl_ssl_backend **ssl_backends = NULL;

    // Initialize CURL easy handle
    easy_handle = curl_easy_init();
    if (!easy_handle) {
        goto cleanup;
    }

    // Initialize CURL multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        goto cleanup;
    }

    // Initialize CURL MIME handle
    mime_handle = curl_mime_init(easy_handle);
    if (!mime_handle) {
        goto cleanup;
    }

    // Create a new MIME part
    mime_part = curl_mime_addpart(mime_handle);
    if (!mime_part) {
        goto cleanup;
    }

    // Initialize global SSL settings
    ssl_res = curl_global_sslset(CURLSSLBACKEND_NONE, NULL, &ssl_backends);
    if (ssl_res != CURLSSLSET_OK) {
        goto cleanup;
    }

    // Prepare data for curl_mime_data
    char mime_data[1024];
    safe_copy(mime_data, data, size);

    // Use curl_mime_data
    res = curl_mime_data(mime_part, mime_data, size);
    if (res != CURLE_OK) {
        goto cleanup;
    }

    // Cleanup
cleanup:
    if (mime_handle) {
        curl_mime_free(mime_handle);
    }
    if (multi_handle) {
        curl_multi_cleanup(multi_handle);
    }
    if (easy_handle) {
        curl_easy_cleanup(easy_handle);
    }

    return 0;
}
