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

// Function to safely allocate memory for a string
char* safe_malloc_string(size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    str[size] = '\0';
    return str;
}

// Function to safely copy a string from fuzz input with size limit
char* safe_strndup_limited(const uint8_t* data, size_t size, size_t limit) {
    if (size == 0 || size > limit) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) return 0;

    // Initialize variables
    CURLU* url_handle = nullptr;
    char* url_part = nullptr;
    CURLcode result = CURLE_OK;
    CURLUcode url_result = CURLUE_OK;

    // Create a new CURLU handle
    url_handle = curl_url();
    if (!url_handle) return 0;

    // Extract parts of the URL from fuzz input
    char* scheme = safe_strndup_limited(data, size / 4, 10);
    char* user = safe_strndup_limited(data + size / 4, size / 4, 20);
    char* password = safe_strndup_limited(data + size / 2, size / 4, 20);
    char* path = safe_strndup_limited(data + 3 * size / 4, size / 4, 50);

    // Set URL parts using curl_url_set
    if (scheme) {
        url_result = curl_url_set(url_handle, CURLUPART_SCHEME, scheme, 0);
        if (url_result != CURLUE_OK) goto cleanup;
    }
    if (user) {
        url_result = curl_url_set(url_handle, CURLUPART_USER, user, 0);
        if (url_result != CURLUE_OK) goto cleanup;
    }
    if (password) {
        url_result = curl_url_set(url_handle, CURLUPART_PASSWORD, password, 0);
        if (url_result != CURLUE_OK) goto cleanup;
    }
    if (path) {
        url_result = curl_url_set(url_handle, CURLUPART_PATH, path, 0);
        if (url_result != CURLUE_OK) goto cleanup;
    }

    // Get the full URL using curl_url_get
    url_result = curl_url_get(url_handle, CURLUPART_URL, &url_part, 0);
    if (url_result != CURLUE_OK) goto cleanup;

    // Use curl_mime_filedata as a placeholder (no actual file handling)
    result = curl_mime_filedata(nullptr, "input_file");
    if (result != CURLE_NOT_BUILT_IN) goto cleanup;

    // Use curl_mime_data_cb as a placeholder (no actual data handling)
    result = curl_mime_data_cb(nullptr, 0, nullptr, nullptr, nullptr, nullptr);
    if (result != CURLE_NOT_BUILT_IN) goto cleanup;

cleanup:
    // Free allocated resources
    if (url_part) free(url_part);
    if (url_handle) curl_url_cleanup(url_handle);
    if (scheme) free(scheme);
    if (user) free(user);
    if (password) free(password);
    if (path) free(path);

    return 0;
}
