#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <memory>

// Function to safely convert a uint8_t array to a C-string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = static_cast<char*>(malloc(size + 1));
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert a uint8_t array to an unsigned int
unsigned int safe_strntoul(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    unsigned int value = strtoul(str, nullptr, 10);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable
    if (size < 1 || size > 1024) return 0;

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create a new CURLU handle
    CURLU* url_handle = curl_url();
    if (!url_handle) {
        curl_global_cleanup();
        return 0;
    }

    // Set URL parts using the fuzz input
    char* scheme = safe_strndup(data, size / 4);
    char* host = safe_strndup(data + size / 4, size / 4);
    char* path = safe_strndup(data + size / 2, size / 4);
    unsigned int port = safe_strntoul(data + 3 * size / 4, size / 4);

    CURLUcode res_url;
    CURLMcode res_multi;

    // Initialize multi_handle and dup_handle here to avoid bypassing initialization
    CURLM* multi_handle = nullptr;
    CURLU* dup_handle = nullptr;

    if (scheme) {
        res_url = curl_url_set(url_handle, CURLUPART_SCHEME, scheme, 0);
        if (res_url != CURLUE_OK) {
            std::cerr << "curl_url_set(SCHEME) failed: " << curl_url_strerror(res_url) << std::endl;
            goto cleanup;
        }
    }

    if (host) {
        res_url = curl_url_set(url_handle, CURLUPART_HOST, host, 0);
        if (res_url != CURLUE_OK) {
            std::cerr << "curl_url_set(HOST) failed: " << curl_url_strerror(res_url) << std::endl;
            goto cleanup;
        }
    }

    if (path) {
        res_url = curl_url_set(url_handle, CURLUPART_PATH, path, 0);
        if (res_url != CURLUE_OK) {
            std::cerr << "curl_url_set(PATH) failed: " << curl_url_strerror(res_url) << std::endl;
            goto cleanup;
        }
    }

    if (port) {
        res_url = curl_url_set(url_handle, CURLUPART_PORT, std::to_string(port).c_str(), 0);
        if (res_url != CURLUE_OK) {
            std::cerr << "curl_url_set(PORT) failed: " << curl_url_strerror(res_url) << std::endl;
            goto cleanup;
        }
    }

    // Duplicate the URL handle
    dup_handle = curl_url_dup(url_handle);
    if (!dup_handle) {
        std::cerr << "curl_url_dup failed" << std::endl;
        goto cleanup;
    }

    // Get URL parts and print them
    char* full_url;
    res_url = curl_url_get(dup_handle, CURLUPART_URL, &full_url, 0);
    if (res_url != CURLUE_OK) {
        std::cerr << "curl_url_get(URL) failed: " << curl_url_strerror(res_url) << std::endl;
        curl_url_cleanup(dup_handle);
        goto cleanup;
    }
    std::cout << "Full URL: " << full_url << std::endl;
    curl_free(full_url);

    // Cleanup duplicated handle
    curl_url_cleanup(dup_handle);

    // Create a multi handle and set options
    multi_handle = curl_multi_init();
    if (!multi_handle) {
        std::cerr << "curl_multi_init failed" << std::endl;
        goto cleanup;
    }

    res_multi = curl_multi_setopt(multi_handle, CURLMOPT_MAXCONNECTS, 10L);
    if (res_multi != CURLM_OK) {
        std::cerr << "curl_multi_setopt failed: " << curl_multi_strerror(res_multi) << std::endl;
        curl_multi_cleanup(multi_handle);
        goto cleanup;
    }

    // Cleanup multi handle
    curl_multi_cleanup(multi_handle);

cleanup:
    // Cleanup original URL handle
    if (url_handle) {
        curl_url_cleanup(url_handle);
    }

    // Free allocated strings
    free(scheme);
    free(host);
    free(path);

    // Cleanup libcurl
    curl_global_cleanup();

    return 0;
}
