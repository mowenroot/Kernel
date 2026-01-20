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
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 4) return 0;

    // Initialize the share handle
    CURLSH* share = curl_share_init();
    if (!share) return 0;

    // Extract options from fuzz input
    int option = safe_atoi(data, 4);
    data += 4;
    size -= 4;

    // Set options on the share handle
    CURLSHcode sh_result = curl_share_setopt(share, (CURLSHoption)option, CURL_LOCK_DATA_DNS);
    if (sh_result != CURLSHE_OK) {
        const char* error_msg = curl_share_strerror(sh_result);
        // Handle error (e.g., log or assert)
        curl_share_cleanup(share);
        return 0;
    }

    // Cleanup the share handle
    sh_result = curl_share_cleanup(share);
    if (sh_result != CURLSHE_OK) {
        const char* error_msg = curl_share_strerror(sh_result);
        // Handle error (e.g., log or assert)
    }

    // Example of using curl_slist_free_all (not directly related to fuzz input)
    struct curl_slist* slist = nullptr;
    curl_slist_free_all(slist);

    return 0;
}
