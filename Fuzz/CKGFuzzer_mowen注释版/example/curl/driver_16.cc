#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a curl_slist from fuzz input
struct curl_slist* create_slist(const uint8_t* data, size_t size) {
    char* header = safe_strndup(data, size);
    if (!header) return NULL;
    struct curl_slist* slist = curl_slist_append(NULL, header);
    free(header);
    return slist;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 1) return 0;

    // Initialize CURL handle
    CURL* easy = curl_easy_init();
    if (!easy) return 0;

    // Initialize MIME handle
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

    // Set MIME data from fuzz input
    CURLcode res = curl_mime_data(part, (const char*)data, size);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Create and set MIME headers from fuzz input
    struct curl_slist* headers = create_slist(data, size);
    if (headers) {
        res = curl_mime_headers(part, headers, 1);
        if (res != CURLE_OK) {
            curl_slist_free_all(headers);
            curl_mime_free(mime);
            curl_easy_cleanup(easy);
            return 0;
        }
    }

    // Cleanup
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(easy);

    return 0;
}
