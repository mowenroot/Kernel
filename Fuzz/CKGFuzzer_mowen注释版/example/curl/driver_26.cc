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
    str[0] = '\0';
    return str;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size > 1024) return 0;

    // Initialize libcurl
    CURL* easy = curl_easy_init();
    if (!easy) return 0;

    // Initialize a new MIME handle
    curl_mime* mime = curl_mime_init(easy);
    if (!mime) {
        curl_easy_cleanup(easy);
        return 0;
    }

    // Create a new MIME part
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Set MIME type
    char* mimetype = safe_strndup(data, size / 2);
    if (mimetype) {
        CURLcode res = curl_mime_type(part, mimetype);
        if (res != CURLE_OK) {
            free(mimetype);
            curl_mime_free(mime);
            curl_easy_cleanup(easy);
            return 0;
        }
        free(mimetype);
    }

    // Set filename
    char* filename = safe_strndup(data + (size / 2), size / 2);
    if (filename) {
        CURLcode res = curl_mime_filename(part, filename);
        if (res != CURLE_OK) {
            free(filename);
            curl_mime_free(mime);
            curl_easy_cleanup(easy);
            return 0;
        }
        free(filename);
    }

    // Set file data (using a placeholder filename)
    CURLcode res = curl_mime_filedata(part, "input_file");
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Set MIME data
    char* mime_data = safe_malloc_string(size);
    if (mime_data) {
        memcpy(mime_data, data, size);
        CURLcode res = curl_mime_data(part, mime_data, size);
        if (res != CURLE_OK) {
            free(mime_data);
            curl_mime_free(mime);
            curl_easy_cleanup(easy);
            return 0;
        }
        free(mime_data);
    }

    // Clean up
    curl_mime_free(mime);
    curl_easy_cleanup(easy);

    return 0;
}
