#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(char *dest, const uint8_t *src, size_t size) {
    size_t min_size = size < CURL_MAX_WRITE_SIZE ? size : CURL_MAX_WRITE_SIZE;
    memcpy(dest, src, min_size);
    dest[min_size] = '\0'; // Null-terminate the string
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize variables
    CURL *easy_handle = NULL;
    curl_mime *mime_handle = NULL;
    curl_mimepart *mime_part = NULL;
    char *mime_data = NULL;
    CURLcode res;
    CURLsslset ssl_set_res;

    // Initialize the CURL easy handle
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

    // Allocate memory for MIME data
    mime_data = (char *)malloc(size + 1);
    if (!mime_data) {
        goto cleanup;
    }

    // Copy fuzz input data to MIME data buffer
    safe_copy(mime_data, data, size);

    // Set MIME data
    res = curl_mime_data(mime_part, mime_data, size);
    if (res != CURLE_OK) {
        goto cleanup;
    }

    // Initialize global SSL settings
    ssl_set_res = curl_global_sslset(CURLSSLBACKEND_NONE, NULL, NULL);
    if (ssl_set_res != CURLSSLSET_OK) {
        goto cleanup;
    }

    // Cleanup
cleanup:
    if (mime_data) {
        free(mime_data);
    }
    if (mime_handle) {
        curl_mime_free(mime_handle);
    }
    if (easy_handle) {
        curl_easy_cleanup(easy_handle);
    }

    return 0;
}
