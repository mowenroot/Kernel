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

// Function to safely copy a string from fuzz input with size limit
char* safe_strncpy(char* dest, const uint8_t* src, size_t n) {
    if (n == 0) return dest;
    size_t i;
    for (i = 0; i < n - 1 && src[i]; ++i) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
    return dest;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize cURL
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Set up a multi handle
    CURLM* multi_handle = curl_multi_init();
    if (!multi_handle) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Buffer for receiving data
    char* recv_buffer = safe_malloc_str(size);
    if (!recv_buffer) {
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Buffer for sending data
    char* send_buffer = safe_strndup(data, size);
    if (!send_buffer) {
        free(recv_buffer);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set options using fuzz input
    CURLcode res;
    res = curl_easy_setopt(curl, CURLOPT_URL, safe_strncpy(safe_malloc_str(size), data, size));
    if (res != CURLE_OK) {
        free(recv_buffer);
        free(send_buffer);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Add easy handle to multi handle
    CURLMcode mres = curl_multi_add_handle(multi_handle, curl);
    if (mres != CURLM_OK) {
        free(recv_buffer);
        free(send_buffer);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Perform the request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        free(recv_buffer);
        free(send_buffer);
        curl_multi_remove_handle(multi_handle, curl);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Send data
    size_t bytes_sent;
    res = curl_easy_send(curl, send_buffer, size, &bytes_sent);
    if (res != CURLE_OK) {
        free(recv_buffer);
        free(send_buffer);
        curl_multi_remove_handle(multi_handle, curl);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Receive data
    size_t bytes_received;
    res = curl_easy_recv(curl, recv_buffer, size, &bytes_received);
    if (res != CURLE_OK) {
        free(recv_buffer);
        free(send_buffer);
        curl_multi_remove_handle(multi_handle, curl);
        curl_multi_cleanup(multi_handle);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Cleanup
    free(recv_buffer);
    free(send_buffer);
    curl_multi_remove_handle(multi_handle, curl);
    curl_multi_cleanup(multi_handle);
    curl_easy_cleanup(curl);

    return 0;
}
