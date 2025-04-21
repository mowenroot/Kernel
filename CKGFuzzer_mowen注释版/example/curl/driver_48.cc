#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = static_cast<char*>(malloc(size + 1));
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to a CURLU* handle
CURLU* safe_curl_url_dup(const uint8_t* data, size_t size) {
    char* url_str = safe_strndup(data, size);
    if (!url_str) return nullptr;
    CURLU* url = curl_url();
    if (!url) {
        free(url_str);
        return nullptr;
    }
    CURLUcode rc = curl_url_set(url, CURLUPART_URL, url_str, 0);
    free(url_str);
    if (rc != CURLUE_OK) {
        curl_url_cleanup(url);
        return nullptr;
    }
    return url;
}

// Function to safely convert fuzz input to a CURL* handle
CURL* safe_curl_easy_init(const uint8_t* data, size_t size) {
    CURL* curl = curl_easy_init();
    if (!curl) return nullptr;
    char* url_str = safe_strndup(data, size);
    if (!url_str) {
        curl_easy_cleanup(curl);
        return nullptr;
    }
    CURLcode rc = curl_easy_setopt(curl, CURLOPT_URL, url_str);
    free(url_str);
    if (rc != CURLE_OK) {
        curl_easy_cleanup(curl);
        return nullptr;
    }
    return curl;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize CURL multi handle
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) return 0;

    // Initialize CURL easy handle
    CURL* easy_handle = safe_curl_easy_init(data, size / 2);
    if (!easy_handle) {
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Add easy handle to multi handle
    CURLMcode add_rc = curl_multi_add_handle(multi_handle, easy_handle);
    if (add_rc != CURLM_OK) {
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Create a MIME part
    curl_mime* mime = curl_mime_init(easy_handle);
    if (!mime) {
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    curl_mimepart* mime_part = curl_mime_addpart(mime);
    if (!mime_part) {
        curl_mime_free(mime);
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Set options for the easy handle
    CURLcode setopt_rc = curl_easy_setopt(easy_handle, CURLOPT_MIMEPOST, mime);
    if (setopt_rc != CURLE_OK) {
        curl_mime_free(mime);
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Create a CURLU handle
    CURLU* url_handle = safe_curl_url_dup(data + size / 2, size / 2);
    if (!url_handle) {
        curl_mime_free(mime);
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Get a part of the URL
    char* url_part = nullptr;
    CURLUcode get_rc = curl_url_get(url_handle, CURLUPART_HOST, &url_part, 0);
    if (get_rc != CURLUE_OK) {
        curl_url_cleanup(url_handle);
        curl_mime_free(mime);
        curl_multi_remove_handle(multi_handle, easy_handle);
        curl_easy_cleanup(easy_handle);
        curl_multi_cleanup(multi_handle);
        return 0;
    }

    // Compare two strings
    int cmp_result = curl_strequal(url_part, "example.com");
    free(url_part);

    // Cleanup
    curl_url_cleanup(url_handle);
    curl_mime_free(mime);
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_easy_cleanup(easy_handle);
    curl_multi_cleanup(multi_handle);

    return 0;
}
