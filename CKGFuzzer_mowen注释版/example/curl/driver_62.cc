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

// Function to safely copy a buffer from fuzz input
void* safe_memdup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    void* mem = malloc(size);
    if (!mem) return nullptr;
    memcpy(mem, data, size);
    return mem;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize cURL
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Set options using fuzz input
    char* url = safe_strndup(data, size);
    if (url) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
    }

    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        // Handle error
        curl_easy_cleanup(curl);
        free(url);
        return 0;
    }

    // WebSocket send (stub)
    size_t sent = 0;
    curl_ws_send(curl, data, size, &sent, 0, 0);

    // WebSocket receive (stub)
    char* recv_buffer = safe_malloc_str(size);
    if (recv_buffer) {
        size_t nread = 0;
        const struct curl_ws_frame* meta = nullptr;
        curl_ws_recv(curl, recv_buffer, size, &nread, &meta);
        free(recv_buffer);
    }

    // WebSocket meta (stub)
    const struct curl_ws_frame* meta = curl_ws_meta(curl);
    (void)meta; // Silence unused variable warning

    // Multi handle (stub)
    CURLM* multi_handle = curl_multi_init();
    if (multi_handle) {
        CURLMcode mres = curl_multi_add_handle(multi_handle, curl);
        if (mres != CURLM_OK) {
            // Handle error
            curl_multi_cleanup(multi_handle);
            curl_easy_cleanup(curl);
            free(url);
            return 0;
        }
        curl_multi_remove_handle(multi_handle, curl);
        curl_multi_cleanup(multi_handle);
    }

    // Cleanup
    curl_easy_cleanup(curl);
    free(url);

    return 0;
}
