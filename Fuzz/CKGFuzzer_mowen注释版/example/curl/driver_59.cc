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

// Function to safely convert fuzz input to a long
long safe_atol(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    long val = strtol(str, nullptr, 10);
    free(str);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 4) return 0;

    // Initialize the CURL handle
    std::unique_ptr<CURL, void(*)(CURL*)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) return 0;

    // Set options using curl_easy_setopt
    CURLcode res;
    long option_id = safe_atol(data, 4);
    res = curl_easy_setopt(curl.get(), static_cast<CURLoption>(option_id), nullptr);
    if (res != CURLE_OK) return 0;

    // Get information using curl_easy_getinfo
    long response_code;
    res = curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &response_code);
    if (res != CURLE_OK) return 0;

    // Query options using curl_easy_option_by_name and curl_easy_option_by_id
    const char* option_name = safe_strndup(data + 4, size - 4);
    if (option_name) {
        const curl_easyoption* option = curl_easy_option_by_name(option_name);
        free((void*)option_name);
    }

    const curl_easyoption* option = curl_easy_option_by_id(static_cast<CURLoption>(option_id));

    // Iterate through options using curl_easy_option_next
    const curl_easyoption* next_option = curl_easy_option_next(nullptr);
    while (next_option) {
        next_option = curl_easy_option_next(next_option);
    }

    return 0;
}
