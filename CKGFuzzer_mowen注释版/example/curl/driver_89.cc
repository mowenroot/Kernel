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

// Function to safely copy a buffer from fuzz input
void* safe_memdup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    void* buf = malloc(size);
    if (!buf) return NULL;
    memcpy(buf, data, size);
    return buf;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize cURL handle
    CURL* curl = curl_easy_init();
    if (!curl) {
        return 0; // Early exit if initialization fails
    }

    // Set URL option
    char* url = safe_strndup(data, size);
    if (url) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        free(url);
    }

    // Set write callback function (dummy implementation)
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        return size * nmemb; // Dummy implementation
    });

    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // Handle error (e.g., log or ignore)
    }

    // Cleanup
    curl_easy_cleanup(curl);

    return 0; // Non-zero return values are reserved for future use.
}
