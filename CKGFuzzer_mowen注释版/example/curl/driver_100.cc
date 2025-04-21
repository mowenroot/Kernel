#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = static_cast<char*>(malloc(size + 1));
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a string
char* safe_malloc_str(size_t size) {
    char* str = static_cast<char*>(malloc(size + 1));
    if (!str) return nullptr;
    str[0] = '\0';
    return str;
}

// Function to safely free allocated memory
void safe_free(void* ptr) {
    if (ptr) free(ptr);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Initialize variables
    char* str1 = safe_strndup(data, size / 2);
    char* str2 = safe_strndup(data + size / 2, size / 2);
    char* url_part = nullptr;
    CURLU* url_handle = curl_url();
    CURLcode mime_result;
    CURLUcode url_result;
    int strnequal_result;
    char* pushheader = nullptr;
    struct curl_slist* headers = nullptr;
    curl_mime* mime = curl_mime_init(nullptr); // Initialize mime object
    curl_mimepart* mime_part = curl_mime_addpart(mime); // Add part to mime object

    // Check for memory allocation failures
    if (!str1 || !str2 || !url_handle || !mime || !mime_part) {
        safe_free(str1);
        safe_free(str2);
        if (url_handle) curl_url_cleanup(url_handle);
        if (mime) curl_mime_free(mime); // Free the mime object
        return 0;
    }

    // Call curl_strnequal
    strnequal_result = curl_strnequal(str1, str2, size / 2);

    // Call curl_pushheader_bynum
    pushheader = curl_pushheader_bynum(nullptr, 0);
    if (pushheader) safe_free(pushheader);

    // Call curl_mime_data_cb
    mime_result = curl_mime_data_cb(mime_part, 0, nullptr, nullptr, nullptr, nullptr);

    // Call curl_mime_headers
    mime_result = curl_mime_headers(mime_part, headers, 0);

    // Call curl_url_get
    url_result = curl_url_get(url_handle, CURLUPART_HOST, &url_part, 0);
    if (url_part) safe_free(url_part);

    // Clean up
    safe_free(str1);
    safe_free(str2);
    curl_url_cleanup(url_handle);
    curl_mime_free(mime); // Free the mime object

    return 0;
}
