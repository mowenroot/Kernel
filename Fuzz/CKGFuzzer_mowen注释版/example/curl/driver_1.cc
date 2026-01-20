#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string with bounds checking
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely create a curl_slist from fuzz input
struct curl_slist* create_slist_from_input(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* header = safe_strndup(data, size);
    if (!header) return nullptr;
    struct curl_slist* slist = curl_slist_append(nullptr, header);
    free(header);
    return slist;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    CURL* easy_handle = curl_easy_init();
    CURLSH* share_handle = curl_share_init();
    curl_mime* mime = curl_mime_init(easy_handle);
    curl_mimepart* mimepart = curl_mime_addpart(mime);
    struct curl_slist* headers = create_slist_from_input(data, size);

    // Perform operations with the provided APIs
    CURLcode mime_result = curl_mime_headers(mimepart, headers, 1);
    if (mime_result != CURLE_NOT_BUILT_IN) {
        // Handle error if curl_mime_headers is ever implemented
        curl_easy_cleanup(easy_handle);
        curl_share_cleanup(share_handle);
        curl_mime_free(mime);
        curl_slist_free_all(headers);
        return 0;
    }

    // Reset the easy handle
    curl_easy_reset(easy_handle);

    // Cleanup resources
    curl_easy_cleanup(easy_handle);
    curl_share_cleanup(share_handle);
    curl_mime_free(mime);
    curl_slist_free_all(headers);

    return 0;
}
