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

// Function to safely create a curl_slist from fuzz input
struct curl_slist* create_slist(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* header = safe_strndup(data, size);
    if (!header) return nullptr;
    struct curl_slist* slist = curl_slist_append(nullptr, header);
    free(header);
    return slist;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 6) return 0;

    // Initialize variables
    CURLcode res;
    curl_mime* mime = curl_mime_init(nullptr);
    curl_mimepart* part = curl_mime_addpart(mime);
    struct curl_slist* headers = nullptr;

    // Extract substrings for API inputs
    size_t mimetype_len = data[0];
    size_t name_len = data[1];
    size_t encoding_len = data[2];
    size_t subparts_len = data[3];
    size_t headers_len = data[4];
    size_t take_ownership = data[5];

    // Ensure we do not exceed buffer bounds
    if (mimetype_len + name_len + encoding_len + subparts_len + headers_len + 6 > size) {
        curl_mime_free(mime);
        return 0;
    }

    // Create MIME type string
    char* mimetype = safe_strndup(data + 6, mimetype_len);
    if (mimetype) {
        res = curl_mime_type(part, mimetype);
        if (res != CURLE_OK) {
            free(mimetype);
            curl_mime_free(mime);
            return 0;
        }
        free(mimetype);
    }

    // Create MIME name string
    char* name = safe_strndup(data + 6 + mimetype_len, name_len);
    if (name) {
        res = curl_mime_name(part, name);
        if (res != CURLE_OK) {
            free(name);
            curl_mime_free(mime);
            return 0;
        }
        free(name);
    }

    // Create MIME encoding string
    char* encoding = safe_strndup(data + 6 + mimetype_len + name_len, encoding_len);
    if (encoding) {
        res = curl_mime_encoder(part, encoding);
        if (res != CURLE_OK) {
            free(encoding);
            curl_mime_free(mime);
            return 0;
        }
        free(encoding);
    }

    // Create MIME subparts
    curl_mime* subparts = curl_mime_init(nullptr);
    if (subparts) {
        res = curl_mime_subparts(part, subparts);
        if (res != CURLE_OK) {
            curl_mime_free(subparts);
            curl_mime_free(mime);
            return 0;
        }
        curl_mime_free(subparts);
    }

    // Create MIME headers
    headers = create_slist(data + 6 + mimetype_len + name_len + encoding_len, headers_len);
    if (headers) {
        res = curl_mime_headers(part, headers, take_ownership);
        if (res != CURLE_OK) {
            curl_slist_free_all(headers);
            curl_mime_free(mime);
            return 0;
        }
        curl_slist_free_all(headers);
    }

    // Clean up
    curl_mime_free(mime);
    return 0;
}
