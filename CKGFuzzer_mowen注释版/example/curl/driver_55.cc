#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <stdexcept>

// Function to safely convert fuzzer input to a C-string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = static_cast<char*>(malloc(size + 1));
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzzer input to an integer
bool safe_strntol(const uint8_t* data, size_t size, long& result) {
    char* endptr;
    char* str = safe_strndup(data, size);
    if (!str) return false;
    result = strtol(str, &endptr, 10);
    free(str);
    return (*endptr == '\0');
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input is large enough to contain at least one URL part
    if (size < 2) return 0;

    // Extract the URL part and flags from the fuzzer input
    CURLUPart url_part = static_cast<CURLUPart>(data[0] % 13); // CURLUPART_LAST is 12
    unsigned int flags = data[1];

    // Create a unique_ptr to manage the CURLU object
    std::unique_ptr<CURLU, void(*)(CURLU*)> url_handle(curl_url(), curl_url_cleanup);
    if (!url_handle) return 0;

    // Set the URL part using the fuzzer input
    char* url_part_str = safe_strndup(data + 2, size - 2);
    if (!url_part_str) return 0;

    CURLUcode set_result = curl_url_set(url_handle.get(), url_part, url_part_str, flags);
    free(url_part_str);

    if (set_result != CURLUE_OK) {
        // Handle error by logging the error message
        const char* error_msg = curl_url_strerror(set_result);
        // Log error_msg (implementation depends on the fuzzing environment)
        return 0;
    }

    // Duplicate the URL handle
    std::unique_ptr<CURLU, void(*)(CURLU*)> dup_handle(curl_url_dup(url_handle.get()), curl_url_cleanup);
    if (!dup_handle) return 0;

    // Retrieve the URL part from the duplicated handle
    char* retrieved_part;
    CURLUcode get_result = curl_url_get(dup_handle.get(), url_part, &retrieved_part, flags);
    
    if (get_result == CURLUE_OK) {
        if (retrieved_part) {
            curl_free(retrieved_part);  
        }
    }else {
        // Handle error by logging the error message
        const char* error_msg = curl_url_strerror(get_result);
        // Log error_msg (implementation depends on the fuzzing environment)
    }

    return 0;
}
