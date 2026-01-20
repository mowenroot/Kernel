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
    char* header = safe_strndup(data, size);
    if (!header) return nullptr;
    struct curl_slist* slist = curl_slist_append(nullptr, header);
    free(header);
    return slist;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize curl handle
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Safely extract URL from fuzz input
    const char* url = safe_strndup(data, size);
    if (!url) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set URL option
    CURLcode res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (res != CURLE_OK) {
        free((void*)url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a curl_slist from fuzz input
    struct curl_slist* headers = create_slist(data, size);
    if (headers) {
        // Set header option
        res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        if (res != CURLE_OK) {
            curl_slist_free_all(headers);
            free((void*)url);
            curl_easy_cleanup(curl);
            return 0;
        }
    }

    // Create a curl_mimepart
    curl_mime* mime = curl_mime_init(curl);
    if (mime) {
        curl_mimepart* part = curl_mime_addpart(mime);
        if (part) {
            // Set MIME headers
            res = curl_mime_headers(part, headers, 1);
            if (res != CURLE_OK) {
                curl_mime_free(mime);
                curl_slist_free_all(headers);
                free((void*)url);
                curl_easy_cleanup(curl);
                return 0;
            }

            // Set MIME subparts
            res = curl_mime_subparts(part, mime);
            if (res != CURLE_OK) {
                curl_mime_free(mime);
                curl_slist_free_all(headers);
                free((void*)url);
                curl_easy_cleanup(curl);
                return 0;
            }
        }
        curl_mime_free(mime);
    }

    // Perform the request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_slist_free_all(headers);
        free((void*)url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Cleanup
    curl_slist_free_all(headers);
    free((void*)url);
    curl_easy_cleanup(curl);

    return 0;
}
