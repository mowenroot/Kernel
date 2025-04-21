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

// Function to safely create a substring from fuzz input
char* safe_substr(const uint8_t* data, size_t size, size_t start, size_t length) {
    if (start >= size || length == 0) return nullptr;
    size_t actual_length = (start + length > size) ? (size - start) : length;
    return safe_strndup(data + start, actual_length);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

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

    // Set MIME type
    char* mimetype = safe_substr(data, size, 0, size / 2);
    if (mimetype) {
        res = curl_mime_type(part, mimetype);
        if (res != CURLE_OK) {
            free(mimetype);
            curl_mime_free(mime);
            return 0;
        }
        free(mimetype);
    }

    // Set filename
    char* filename = safe_substr(data, size, size / 2, size / 2);
    if (filename) {
        res = curl_mime_filename(part, filename);
        if (res != CURLE_OK) {
            free(filename);
            curl_mime_free(mime);
            return 0;
        }
        free(filename);
    }

    // Set file data (simulated)
    res = curl_mime_filedata(part, "input_file");
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        return 0;
    }

    // Set raw data
    res = curl_mime_data(part, (const char*)data, size);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        return 0;
    }

    // Clean up
    curl_mime_free(mime);
    return 0;
}
