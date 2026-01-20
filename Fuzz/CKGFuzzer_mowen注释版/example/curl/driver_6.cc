#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <stdexcept>

// Function to safely allocate memory and handle errors
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        throw std::runtime_error("Memory allocation failed");
    }
    return ptr;
}

// Function to safely free allocated memory
template <typename T>
void safe_free(T* ptr) {
    free(ptr);
}

// Function to safely copy a string and handle errors
char* safe_strndup(const char* str, size_t n) {
    char* new_str = static_cast<char*>(malloc(n + 1));
    if (!new_str) {
        throw std::runtime_error("Memory allocation failed");
    }
    strncpy(new_str, str, n);
    new_str[n] = '\0';
    return new_str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Initialize a CURL handle
    CURL* curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Convert the fuzz input to a C-string
    char* input_str = safe_strndup(reinterpret_cast<const char*>(data), size);

    // Perform URL encoding
    char* encoded_str = curl_easy_escape(curl, input_str, static_cast<int>(size));
    if (!encoded_str) {
        curl_easy_cleanup(curl);
        safe_free(input_str);
        return 0;
    }

    // Perform URL decoding
    int decoded_len = 0;
    char* decoded_str = curl_easy_unescape(curl, encoded_str, static_cast<int>(strlen(encoded_str)), &decoded_len);
    if (!decoded_str) {
        curl_easy_cleanup(curl);
        safe_free(input_str);
        curl_free(encoded_str);
        return 0;
    }

    // Set an option using curl_easy_setopt
    CURLcode res = curl_easy_setopt(curl, CURLOPT_URL, decoded_str);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        safe_free(input_str);
        curl_free(encoded_str);
        curl_free(decoded_str);
        return 0;
    }

    // Clean up resources
    curl_easy_cleanup(curl);
    safe_free(input_str);
    curl_free(encoded_str);
    curl_free(decoded_str);

    return 0;
}
