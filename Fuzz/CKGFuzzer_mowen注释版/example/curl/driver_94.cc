#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>  // Include for va_list, va_start, va_end

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely format a string using curl_mvsnprintf
int safe_curl_mvsnprintf(char* buffer, size_t maxlength, const char* format, ...) {
    if (!buffer || !format || maxlength == 0) return -1;
    va_list ap;
    va_start(ap, format);  // Correctly initialize va_list
    int result = curl_mvsnprintf(buffer, maxlength, format, ap);
    va_end(ap);  // Correctly end va_list
    return result;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize CURL handle
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Safely copy fuzz input to a string
    char* url = safe_strndup(data, size);
    if (!url) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set URL option using curl_easy_setopt
    CURLcode res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (res != CURLE_OK) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Initialize MIME part
    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a MIME part
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set MIME part data using curl_mime_data_cb
    res = curl_mime_data_cb(part, size, nullptr, nullptr, nullptr, (void*)data);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set MIME part headers using curl_mime_headers
    res = curl_mime_headers(part, nullptr, 0);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Perform a safe string formatting using curl_mvsnprintf
    char buffer[256];
    int len = safe_curl_mvsnprintf(buffer, sizeof(buffer), "URL: %s", url);  // Pass url directly
    if (len < 0) {
        curl_mime_free(mime);
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Cleanup
    curl_mime_free(mime);
    free(url);
    curl_easy_cleanup(curl);

    return 0;
}
