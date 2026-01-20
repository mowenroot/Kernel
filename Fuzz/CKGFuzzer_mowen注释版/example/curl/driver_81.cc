#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to read data from the fuzzer input
static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp) {
    const uint8_t *data = (const uint8_t *)userp;
    size_t data_size = *(size_t *)userp;
    size_t total_size = size * nmemb;

    if (data_size < total_size) {
        total_size = data_size;
    }

    memcpy(ptr, data, total_size);
    return total_size;
}

// Function to seek within the fuzzer input (not implemented)
static int seek_callback(void *userp, curl_off_t offset, int origin) {
    (void)userp;
    (void)offset;
    (void)origin;
    return CURL_SEEKFUNC_CANTSEEK;
}

// Function to free the fuzzer input (not implemented)
static void free_callback(void *userp) {
    (void)userp;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    CURL *easy = curl_easy_init();
    if (!easy) {
        return 0;
    }

    curl_mime *mime = curl_mime_init(easy);
    if (!mime) {
        curl_easy_cleanup(easy);
        return 0;
    }

    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Set MIME type (not implemented, but we still call it)
    CURLcode res = curl_mime_type(part, "application/octet-stream");
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Set MIME headers (not implemented, but we still call it)
    struct curl_slist *headers = NULL;
    res = curl_mime_headers(part, headers, 1);
    if (res != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Set MIME data callback
    res = curl_mime_data_cb(part, size, read_callback, seek_callback, free_callback, (void *)data);
    if (res != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Clean up
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(easy);

    return 0;
}
