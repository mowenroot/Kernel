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

// Function to safely convert fuzz input to an integer
int safe_atoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize libcurl
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Initialize MIME structure
    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a MIME part
    curl_mimepart* mimepart = curl_mime_addpart(mime);
    if (!mimepart) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set options using fuzz input
    const char* url = safe_strndup(data, size);
    if (url) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        free((void*)url);
    }

    // Pause the transfer using fuzz input
    int pause_action = safe_atoi(data, size) % 4; // CURLPAUSE_* values are 0-3
    curl_easy_pause(curl, pause_action);

    // Perform the transfer
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // Handle error (e.g., log or ignore)
    }

    // Clean up resources
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}
