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
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize cURL
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    // Extract parts of the input for different API calls
    size_t url_size = size / 4;
    size_t option_size = size / 4;
    size_t info_size = size / 4;
    size_t escape_size = size / 4;

    // Extract URL from input
    char* url = safe_strndup(data, url_size);
    if (!url) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set URL option
    CURLcode res = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (res != CURLE_OK) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Extract option value from input
    long option_value = safe_atoi(data + url_size, option_size);
    res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, option_value);
    if (res != CURLE_OK) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Perform the request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Extract info type from input
    long info_type = safe_atoi(data + url_size + option_size, info_size);
    long response_code;
    res = curl_easy_getinfo(curl, (CURLINFO)info_type, &response_code);
    if (res != CURLE_OK) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Extract string to escape from input
    char* escape_str = safe_strndup(data + url_size + option_size + info_size, escape_size);
    if (!escape_str) {
        free(url);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Escape the string
    char* escaped_str = curl_easy_escape(curl, escape_str, escape_size);
    if (escaped_str) {
        free(escaped_str);
    }

    // Unescape the string
    int unescaped_len;
    char* unescaped_str = curl_easy_unescape(curl, escape_str, escape_size, &unescaped_len);
    if (unescaped_str) {
        free(unescaped_str);
    }

    // Clean up
    free(escape_str);
    free(url);
    curl_easy_cleanup(curl);

    return 0;
}
