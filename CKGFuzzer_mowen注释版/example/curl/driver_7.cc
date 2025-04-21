#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <iostream>

// Function to convert fuzzer input to a CURLcode
CURLcode get_curl_code(const uint8_t *data, size_t size) {
    if (size == 0) {
        return CURLE_OK; // Default to no error if no input
    }
    // Ensure the input is within the valid range of CURLcode
    uint8_t code = data[0] % (CURL_LAST + 1);
    return static_cast<CURLcode>(code);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize global state for libcurl
    CURLcode global_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (global_init_result != CURLE_OK) {
        std::cerr << "curl_global_init failed: " << curl_easy_strerror(global_init_result) << std::endl;
        return 0;
    }

    // Initialize a new Curl easy handle
    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "curl_easy_init failed" << std::endl;
        curl_global_cleanup();
        return 0;
    }

    // Convert fuzzer input to a CURLcode and get the corresponding error message
    CURLcode error_code = get_curl_code(data, size);
    const char *error_message = curl_easy_strerror(error_code);
    std::cout << "Error Code: " << error_code << ", Message: " << error_message << std::endl;

    // Clean up the Curl easy handle
    curl_easy_cleanup(curl);

    // Clean up global resources used by libcurl
    curl_global_cleanup();

    return 0;
}
