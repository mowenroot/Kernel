#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

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
int safe_strntoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 10) return 0;

    // Initialize CURL handle
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Extract substrings for different API inputs
    size_t url_size = size / 3;
    size_t option_size = (size - url_size) / 2;
    size_t value_size = size - url_size - option_size;

    char* url = safe_strndup(data, url_size);
    char* option_str = safe_strndup(data + url_size, option_size);
    char* value_str = safe_strndup(data + url_size + option_size, value_size);

    if (!url || !option_str || !value_str) {
        curl_easy_cleanup(curl);
        free(url);
        free(option_str);
        free(value_str);
        return 0;
    }

    // Convert option string to CURLoption
    CURLoption option = static_cast<CURLoption>(safe_strntoi((const uint8_t*)option_str, option_size));

    // Set CURL options
    CURLcode res = curl_easy_setopt(curl, option, value_str);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        free(url);
        free(option_str);
        free(value_str);
        return 0;
    }

    // Encode URL
    char* encoded_url = curl_easy_escape(curl, url, url_size);
    if (!encoded_url) {
        curl_easy_cleanup(curl);
        free(url);
        free(option_str);
        free(value_str);
        return 0;
    }

    // Set the encoded URL as the URL to perform
    res = curl_easy_setopt(curl, CURLOPT_URL, encoded_url);
    if (res != CURLE_OK) {
        curl_free(encoded_url);
        curl_easy_cleanup(curl);
        free(url);
        free(option_str);
        free(value_str);
        return 0;
    }

    // Perform the CURL request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_free(encoded_url);
        curl_easy_cleanup(curl);
        free(url);
        free(option_str);
        free(value_str);
        return 0;
    }

    // Unescape the URL for further processing
    int unescaped_length = 0;
    char* unescaped_url = curl_easy_unescape(curl, encoded_url, strlen(encoded_url), &unescaped_length);
    if (!unescaped_url) {
        curl_free(encoded_url);
        curl_easy_cleanup(curl);
        free(url);
        free(option_str);
        free(value_str);
        return 0;
    }

    // Clean up
    curl_free(encoded_url);
    curl_free(unescaped_url);
    curl_easy_cleanup(curl);
    free(url);
    free(option_str);
    free(value_str);

    return 0;
}
