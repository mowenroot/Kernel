#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to a CURLMoption
CURLMoption safe_convert_to_curlmoption(const uint8_t *data, size_t size) {
    if (size < sizeof(CURLMoption)) {
        return CURLMOPT_MAXCONNECTS; // Default safe option
    }
    return static_cast<CURLMoption>(*reinterpret_cast<const CURLMoption*>(data));
}

// Function to safely convert fuzz input to a curl_socket_t
curl_socket_t safe_convert_to_curl_socket_t(const uint8_t *data, size_t size) {
    if (size < sizeof(curl_socket_t)) {
        return CURL_SOCKET_BAD; // Default safe value
    }
    return *reinterpret_cast<const curl_socket_t*>(data);
}

// Function to safely convert fuzz input to a void*
void* safe_convert_to_void_ptr(const uint8_t *data, size_t size) {
    if (size < sizeof(void*)) {
        return nullptr; // Default safe value
    }
    return const_cast<void*>(reinterpret_cast<const void*>(data));
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    CURLM *multi_handle = nullptr;
    CURLMcode res;

    // Initialize the multi handle
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        return 0; // Failed to initialize
    }

    // Set options using fuzz input
    CURLMoption option = safe_convert_to_curlmoption(data, size);
    void *userp = safe_convert_to_void_ptr(data, size);
    res = curl_multi_setopt(multi_handle, option, userp);
    if (res != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        return 0; // Failed to set option
    }

    // Assign a socket using fuzz input
    curl_socket_t socket = safe_convert_to_curl_socket_t(data, size);
    void *hashp = safe_convert_to_void_ptr(data, size);
    res = curl_multi_assign(multi_handle, socket, hashp);
    if (res != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        return 0; // Failed to assign socket
    }

    // Remove a handle (simulate with a null handle for fuzzing)
    CURL *easy_handle = nullptr; // Simulate a handle
    res = curl_multi_remove_handle(multi_handle, easy_handle);
    if (res != CURLM_OK) {
        curl_multi_cleanup(multi_handle);
        return 0; // Failed to remove handle
    }

    // Cleanup the multi handle
    res = curl_multi_cleanup(multi_handle);
    if (res != CURLM_OK) {
        return 0; // Failed to cleanup
    }

    return 0; // Success
}
