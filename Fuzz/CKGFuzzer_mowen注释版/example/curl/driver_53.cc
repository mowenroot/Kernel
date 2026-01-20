#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely allocate memory and copy data from fuzz input
void* safe_alloc_and_copy(const uint8_t* src, size_t size) {
    if (src && size > 0) {
        void* dest = malloc(size);
        if (dest) {
            memcpy(dest, src, size);
            return dest;
        }
    }
    return NULL;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within reasonable limits to prevent excessive memory usage
    if (size < 1 || size > 1024) {
        return 0;
    }

    // Initialize variables
    CURL* easy_handle = NULL;
    curl_mime* mime_handle = NULL;
    curl_mimepart* mime_part = NULL;
    CURLU* url_handle = NULL;
    void* buffer = NULL;
    size_t nread = 0;
    const struct curl_ws_frame* meta = NULL;
    CURLcode result;

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

    // Allocate and copy data to the buffer
    buffer = safe_alloc_and_copy(data, size);
    if (!buffer) {
        goto cleanup;
    }

    // Attempt to receive WebSocket data (placeholder function)
    result = curl_ws_recv(easy_handle, buffer, size, &nread, &meta);
    if (result != CURLE_NOT_BUILT_IN) {
        // Handle unexpected result
        goto cleanup;
    }

    // Cleanup URL handle (if used)
    if (url_handle) {
        curl_url_cleanup(url_handle);
    }

cleanup:
    // Free allocated resources
    if (buffer) {
        free(buffer);
    }
    if (mime_handle) {
        curl_mime_free(mime_handle);
    }
    if (easy_handle) {
        curl_easy_cleanup(easy_handle);
    }

    return 0;
}
