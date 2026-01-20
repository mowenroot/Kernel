#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <stdexcept>

// Function to safely convert fuzzer input to a C-string
char* SafeStringFromFuzzInput(const uint8_t* data, size_t size) {
    if (size == 0 || data == nullptr) {
        return nullptr;
    }
    char* str = static_cast<char*>(malloc(size + 1));
    if (str == nullptr) {
        return nullptr;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely free allocated memory
void SafeFree(void* ptr) {
    if (ptr != nullptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Create a unique_ptr to manage the CURLU object
    std::unique_ptr<CURLU, void(*)(CURLU*)> urlHandle(curl_url(), curl_url_cleanup);
    if (!urlHandle) {
        return 0;
    }

    // Convert fuzzer input to a C-string
    char* urlStr = SafeStringFromFuzzInput(data, size);
    if (!urlStr) {
        return 0;
    }

    // Set the URL part
    CURLUcode setResult = curl_url_set(urlHandle.get(), CURLUPART_URL, urlStr, 0);
    if (setResult != CURLUE_OK) {
        SafeFree(urlStr);
        return 0;
    }

    // Duplicate the URL handle
    std::unique_ptr<CURLU, void(*)(CURLU*)> dupHandle(curl_url_dup(urlHandle.get()), curl_url_cleanup);
    if (!dupHandle) {
        SafeFree(urlStr);
        return 0;
    }

    // Get the URL part
    char* retrievedUrl = nullptr;
    CURLUcode getResult = curl_url_get(dupHandle.get(), CURLUPART_URL, &retrievedUrl, 0);
    if (getResult != CURLUE_OK) {
        SafeFree(urlStr);
        curl_free(retrievedUrl);
        return 0;
    }

    // Compare the original and retrieved URLs
    if (strcmp(urlStr, retrievedUrl) != 0) {
        SafeFree(urlStr);
        curl_free(retrievedUrl);
        return 0;
    }

    // Cleanup
    SafeFree(urlStr);
    curl_free(retrievedUrl);

    return 0;
}
