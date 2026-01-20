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
    char* str = safe_strndup(data, size);
    if (!str) return nullptr;
    struct curl_slist* slist = curl_slist_append(nullptr, str);
    free(str);
    return slist;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 5) return 0;

    // Initialize libcurl
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Create a MIME structure
    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a MIME part
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set the name of the MIME part
    char* name = safe_strndup(data, size / 5);
    if (name) {
        CURLcode res = curl_mime_name(part, name);
        if (res != CURLE_OK) {
            free(name);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        free(name);
    }

    // Set the file data of the MIME part
    char* filedata = safe_strndup(data + size / 5, size / 5);
    if (filedata) {
        CURLcode res = curl_mime_filedata(part, filedata);
        if (res != CURLE_OK) {
            free(filedata);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        free(filedata);
    }

    // Set the data of the MIME part
    char* mime_data = safe_strndup(data + 2 * (size / 5), size / 5);
    if (mime_data) {
        CURLcode res = curl_mime_data(part, mime_data, size / 5);
        if (res != CURLE_OK) {
            free(mime_data);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        free(mime_data);
    }

    // Set the headers of the MIME part
    struct curl_slist* headers = create_slist(data + 3 * (size / 5), size / 5);
    if (headers) {
        CURLcode res = curl_mime_headers(part, headers, 1);
        if (res != CURLE_OK) {
            curl_slist_free_all(headers);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        curl_slist_free_all(headers);
    }

    // Set the subparts of the MIME part
    curl_mime* subparts = curl_mime_init(curl);
    if (subparts) {
        CURLcode res = curl_mime_subparts(part, subparts);
        if (res != CURLE_OK) {
            curl_mime_free(subparts);
            curl_mime_free(mime);
            curl_easy_cleanup(curl);
            return 0;
        }
        curl_mime_free(subparts);
    }

    // Clean up
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}
