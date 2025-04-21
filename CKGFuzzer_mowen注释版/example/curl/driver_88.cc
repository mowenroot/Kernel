#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added for fprintf

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
curl_mimepart* safe_mimepart_init(curl_mime* mime) {
    if (!mime) {
        fprintf(stderr, "Failed to initialize curl_mime\n");
        return nullptr;
    }

    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        fprintf(stderr, "Failed to initialize curl_mimepart\n");
        return nullptr;
    }

    return part;
}

// Function to safely allocate and initialize a curl_mime
curl_mime* safe_mime_init(CURL* easy_handle) {
    curl_mime* mime = curl_mime_init(easy_handle);
    if (!mime) {
        fprintf(stderr, "Failed to initialize curl_mime\n");
        return nullptr;
    }
    return mime;
}

// Function to safely allocate and initialize a curl_slist
curl_slist* safe_slist_append(curl_slist* list, const char* str) {
    curl_slist* new_list = curl_slist_append(list, str);
    if (!new_list) {
        fprintf(stderr, "Failed to append to curl_slist\n");
        return nullptr;
    }
    return new_list;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0; // Need at least 4 bytes for basic operations

    // Initialize libcurl
    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) {
        fprintf(stderr, "Failed to initialize curl easy handle\n");
        return 0;
    }

    // Initialize curl_multi_handle
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) {
        fprintf(stderr, "Failed to initialize curl multi handle\n");
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Initialize curl_mime and curl_mimepart
    curl_mime* mime = safe_mime_init(easy_handle);
    if (!mime) {
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    curl_mimepart* mimepart = safe_mimepart_init(mime);
    if (!mimepart) {
        curl_mime_free(mime);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Extract data for API calls
    char* encoding = safe_strndup(data, size / 2);
    char* header_str = safe_strndup(data + (size / 2), size / 2);
    if (!encoding || !header_str) {
        free(encoding);
        free(header_str);
        curl_mime_free(mime);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Create curl_slist for headers
    curl_slist* headers = safe_slist_append(nullptr, header_str);
    if (!headers) {
        free(encoding);
        free(header_str);
        curl_mime_free(mime);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Call curl_mime_encoder
    CURLcode res_encoder = curl_mime_encoder(mimepart, encoding);
    if (res_encoder != CURLE_OK) {
        fprintf(stderr, "curl_mime_encoder failed: %d\n", res_encoder);
    }

    // Call curl_mime_headers
    CURLcode res_headers = curl_mime_headers(mimepart, headers, 1);
    if (res_headers != CURLE_OK) {
        fprintf(stderr, "curl_mime_headers failed: %d\n", res_headers);
    }

    // Call curl_mime_subparts
    CURLcode res_subparts = curl_mime_subparts(mimepart, mime);
    if (res_subparts != CURLE_OK) {
        fprintf(stderr, "curl_mime_subparts failed: %d\n", res_subparts);
    }

    // Call curl_easy_pause
    CURLcode res_pause = curl_easy_pause(easy_handle, CURLPAUSE_ALL);
    if (res_pause != CURLE_OK) {
        fprintf(stderr, "curl_easy_pause failed: %d\n", res_pause);
    }

    // Call curl_multi_socket
    int running_handles;
    CURLMcode res_multi_socket = curl_multi_socket(multi_handle, 0, &running_handles);
    if (res_multi_socket != CURLM_OK) {
        fprintf(stderr, "curl_multi_socket failed: %d\n", res_multi_socket);
    }

    // Cleanup
    free(encoding);
    free(header_str);
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_multi_cleanup(multi_handle);
    curl_easy_cleanup(easy_handle);

    return 0;
}
