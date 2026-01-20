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

// Function to safely allocate and initialize a curl_mimepart
curl_mimepart* safe_mimepart_init() {
    CURL* curl = curl_easy_init();
    if (!curl) return nullptr;

    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return nullptr;
    }

    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return nullptr;
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    return part;
}

// Function to safely allocate and initialize a curl_mime
curl_mime* safe_mime_init() {
    CURL* curl = curl_easy_init();
    if (!curl) return nullptr;

    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return nullptr;
    }

    curl_easy_cleanup(curl);
    return mime;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size > 1024) return 0;

    // Initialize variables
    curl_mimepart* part = safe_mimepart_init();
    if (!part) return 0;

    curl_mime* mime = safe_mime_init();
    if (!mime) {
        curl_mime_free(mime);
        return 0;
    }

    // Set MIME type
    char* mimetype = safe_strndup(data, size / 4);
    if (mimetype) {
        CURLcode res = curl_mime_type(part, mimetype);
        if (res != CURLE_OK) {
            free(mimetype);
            curl_mime_free(mime);
            return 0;
        }
        free(mimetype);
    }

    // Set MIME encoder
    char* encoder = safe_strndup(data + size / 4, size / 4);
    if (encoder) {
        CURLcode res = curl_mime_encoder(part, encoder);
        if (res != CURLE_OK) {
            free(encoder);
            curl_mime_free(mime);
            return 0;
        }
        free(encoder);
    }

    // Set MIME data callback
    CURLcode res = curl_mime_data_cb(part, size / 2, nullptr, nullptr, nullptr, nullptr);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        return 0;
    }

    // Set MIME subparts
    res = curl_mime_subparts(part, mime);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        return 0;
    }

    // Clean up
    curl_mime_free(mime);

    return 0;
}
