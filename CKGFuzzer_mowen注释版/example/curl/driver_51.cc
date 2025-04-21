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
    if (size < 10) return 0;

    // Initialize libcurl
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Create a curl_mimepart
    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);

    // Set encoding for the part
    const char* encoding = safe_strndup(data, 5);
    if (encoding) {
        CURLcode res = curl_mime_encoder(part, encoding);
        if (res != CURLE_OK) {
            free((void*)encoding);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        free((void*)encoding);
    }

    // Set subparts for the part
    curl_mime* subparts = curl_mime_init(curl);
    CURLcode res = curl_mime_subparts(part, subparts);
    if (res != CURLE_OK) {
        curl_mime_free(subparts);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }
    curl_mime_free(subparts);

    // Set headers for the part
    struct curl_slist* headers = create_slist(data + 5, size - 5);
    if (headers) {
        res = curl_mime_headers(part, headers, 1);
        if (res != CURLE_OK) {
            curl_slist_free_all(headers);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        curl_slist_free_all(headers);
    }

    // URL escape a string
    const char* input_str = safe_strndup(data, size);
    if (input_str) {
        char* escaped_str = curl_easy_escape(curl, input_str, size);
        if (escaped_str) {
            free(escaped_str);
        }
        free((void*)input_str);
    }

    // URL unescape a string
    const char* input_str_unescape = safe_strndup(data, size);
    if (input_str_unescape) {
        char* unescaped_str = curl_unescape(input_str_unescape, size);
        if (unescaped_str) {
            free(unescaped_str);
        }
        free((void*)input_str_unescape);
    }

    // Clean up
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}
