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
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Initialize libcurl
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Create a MIME structure
    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a new MIME part
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set MIME type
    char* mimetype = safe_strndup(data, 5); // Change to non-const char*
    if (mimetype) {
        CURLcode res = curl_mime_type(part, mimetype);
        if (res != CURLE_OK) {
            free(mimetype); // No need to change here
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        free(mimetype); // No need to change here
    }

    // Set filename
    char* filename = safe_strndup(data + 5, 10); // Change to non-const char*
    if (filename) {
        CURLcode res = curl_mime_filename(part, filename);
        if (res != CURLE_OK) {
            free(filename); // No need to change here
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        free(filename); // No need to change here
    }

    // Add data to the MIME part
    CURLcode res = curl_mime_data(part, (const char*)(data + 15), size - 15);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create subparts if there's enough data
    if (size > 25) {
        curl_mime* subparts = curl_mime_init(curl);
        if (subparts) {
            res = curl_mime_subparts(part, subparts);
            if (res != CURLE_OK) {
                curl_mime_free(subparts);
                curl_mime_free(mime);
                curl_easy_cleanup(curl);
                return 0;
            }
        }
    }

    // Add headers if there's enough data
    if (size > 35) {
        struct curl_slist* headers = create_slist(data + 25, size - 25);
        if (headers) {
            res = curl_mime_headers(part, headers, 1);
            if (res != CURLE_OK) {
                curl_slist_free_all(headers);
                curl_mime_free(mime);
                curl_easy_cleanup(curl);
                return 0;
            }
        }
    }

    // Clean up
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}
