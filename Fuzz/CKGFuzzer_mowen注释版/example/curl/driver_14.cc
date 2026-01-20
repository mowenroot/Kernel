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
    memset(str, 0, size + 1);
    return str;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size < 1 || size > 1024) return 0;

    // Initialize variables
    CURLcode res;
    curl_mime* mime = curl_mime_init(nullptr);
    if (!mime) return 0;

    // Create a new MIME part
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        return 0;
    }

    // Derive a filename from the fuzz input
    char* filename = safe_strndup(data, size);
    if (!filename) {
        curl_mime_free(mime);
        return 0;
    }

    // Set file data to the MIME part
    res = curl_mime_filedata(part, filename);
    if (res != CURLE_OK) {
        curl_free(filename);
        curl_mime_free(mime);
        return 0;
    }

    // Derive a string for MIME data callback
    char* mime_data = safe_malloc_string(size);
    if (!mime_data) {
        curl_free(filename);
        curl_mime_free(mime);
        return 0;
    }

    // Set MIME data callback
    res = curl_mime_data_cb(part, size, nullptr, nullptr, nullptr, mime_data);
    if (res != CURLE_OK) {
        curl_free(filename);
        curl_free(mime_data);
        curl_mime_free(mime);
        return 0;
    }

    // Set subparts to the MIME part
    res = curl_mime_subparts(part, mime);
    if (res != CURLE_OK) {
        curl_free(filename);
        curl_free(mime_data);
        curl_mime_free(mime);
        return 0;
    }

    // Clean up
    curl_free(filename);
    curl_free(mime_data);
    curl_mime_free(mime);

    return 0;
}
