#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <stdexcept>

// Function to safely convert a uint8_t array to a C-string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = static_cast<char*>(malloc(size + 1));
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely free a C-string
void safe_free(char* str) {
    free(str);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) return 0;

    // Create a unique_ptr to manage the CURLU object
    std::unique_ptr<CURLU, void(*)(CURLU*)> url_handle(curl_url(), curl_url_cleanup);
    if (!url_handle) return 0;

    // Convert fuzzer input to a C-string
    char* input_str = safe_strndup(data, size);
    if (!input_str) return 0;

    // Set the URL part using the fuzzer input
    CURLUcode set_result = curl_url_set(url_handle.get(), CURLUPART_URL, input_str, 0);
    if (set_result != CURLUE_OK) {
        safe_free(input_str);
        return 0;
    }

    // Duplicate the URL handle
    std::unique_ptr<CURLU, void(*)(CURLU*)> dup_handle(curl_url_dup(url_handle.get()), curl_url_cleanup);
    if (!dup_handle) {
        safe_free(input_str);
        return 0;
    }

    // Retrieve the URL part
    char* retrieved_url = nullptr;
    CURLUcode get_result = curl_url_get(dup_handle.get(), CURLUPART_URL, &retrieved_url, 0);
    if (get_result != CURLUE_OK) {
        safe_free(input_str);
        curl_free(retrieved_url);
        return 0;
    }

    // Compare the original input with the retrieved URL
    if (strcmp(input_str, retrieved_url) != 0) {
        // Log the discrepancy for debugging
        fprintf(stderr, "Input and retrieved URL mismatch: %s != %s\n", input_str, retrieved_url);
    }

    // Clean up
    safe_free(input_str);
    curl_free(retrieved_url);

    return 0;
}
