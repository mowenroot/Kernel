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

// Function to safely allocate and copy a string from fuzz input
char* safe_strndup_from_fuzz(const uint8_t* data, size_t size, size_t max_size) {
    if (size > max_size) size = max_size;
    return safe_strndup(data, size);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize libcurl
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Create a MIME part
    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a MIME part for operations
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set MIME type
    char* mimetype = safe_strndup_from_fuzz(data, size, 64);
    if (mimetype) {
        CURLcode res = curl_mime_type(part, mimetype);
        if (res != CURLE_OK) {
            free(mimetype);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        free(mimetype);
    }

    // Set filename
    char* filename = safe_strndup_from_fuzz(data + 64, size - 64, 64);
    if (filename) {
        CURLcode res = curl_mime_filename(part, filename);
        if (res != CURLE_OK) {
            free(filename);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        free(filename);
    }

    // Set data using curl_mime_data
    size_t data_size = size > 128 ? 128 : size;
    CURLcode res = curl_mime_data(part, (const char*)data, data_size);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Clean up
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}
