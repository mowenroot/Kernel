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

// Function to safely allocate memory for a string
char* safe_malloc_str(size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    str[0] = '\0';
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize CURL and MIME handles
    CURL* easy_handle = curl_easy_init();
    if (!easy_handle) return 0;

    curl_mime* mime_handle = curl_mime_init(easy_handle);
    if (!mime_handle) {
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Create a MIME part
    curl_mimepart* mime_part = curl_mime_addpart(mime_handle);
    if (!mime_part) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Set MIME part name
    char* mime_name = safe_strndup(data, size);
    if (mime_name) {
        CURLcode res = curl_mime_name(mime_part, mime_name);
        if (res != CURLE_OK) {
            free(mime_name);
            curl_mime_free(mime_handle);
            curl_easy_cleanup(easy_handle);
            return 0;
        }
        free(mime_name);
    }

    // Set MIME part data
    char* mime_data = safe_malloc_str(size);
    if (mime_data) {
        memcpy(mime_data, data, size);
        CURLcode res = curl_mime_data(mime_part, mime_data, size);
        if (res != CURLE_OK) {
            free(mime_data);
            curl_mime_free(mime_handle);
            curl_easy_cleanup(easy_handle);
            return 0;
        }
        free(mime_data);
    }

    // Set CURL options
    CURLcode res = curl_easy_setopt(easy_handle, CURLOPT_URL, "http://example.com");
    if (res != CURLE_OK) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Initialize a multi handle and add the easy handle to it
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    CURLMcode mres = curl_multi_add_handle(multi_handle, easy_handle);
    if (mres != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        curl_mime_free(mime_handle);
        curl_easy_cleanup(easy_handle);
        return 0;
    }

    // Perform the multi handle operations
    int still_running;
    curl_multi_perform(multi_handle, &still_running);

    // Clean up resources
    curl_multi_remove_handle(multi_handle, easy_handle);
    curl_multi_cleanup(multi_handle);
    curl_mime_free(mime_handle);
    curl_easy_cleanup(easy_handle);

    return 0;
}
