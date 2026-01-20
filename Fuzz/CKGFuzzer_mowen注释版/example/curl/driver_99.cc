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

// Function to safely create a CURL string list from fuzz input
struct curl_slist* create_slist(const uint8_t* data, size_t size) {
    struct curl_slist* slist = NULL;
    char* str = safe_strndup(data, size);
    if (str) {
        slist = curl_slist_append(slist, str);
        free(str);
    }
    return slist;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize CURL handle
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Safely create a string from fuzz input
    char* url = safe_strndup(data, size);
    if (!url) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set CURL options
    CURLcode res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (res != CURLE_OK) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a MIME part
    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a string list
    struct curl_slist* slist = create_slist(data, size);
    if (slist) {
        res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
        if (res != CURLE_OK) {
            curl_slist_free_all(slist);
            curl_mime_free(mime);
            free(url);
            curl_easy_cleanup(curl);
            return 0;
        }
    }

    // Perform the CURL operation
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_slist_free_all(slist);
        curl_mime_free(mime);
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Clean up resources
    curl_slist_free_all(slist);
    curl_mime_free(mime);
    free(url);
    curl_easy_cleanup(curl);

    return 0;
}
