#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely free a string
void safe_free(char **str) {
    if (*str) {
        free(*str);
        *str = NULL;
    }
}

// Function to safely free a curl_mime structure
void safe_mime_free(curl_mime **mime) {
    if (*mime) {
        curl_mime_free(*mime);
        *mime = NULL;
    }
}

// Function to safely free a curl_mimepart structure
void safe_mimepart_free(curl_mimepart **part) {
    if (*part) {
        *part = NULL;
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024) {
        return 0;
    }

    // Initialize variables
    CURLcode res;
    char *unescaped_str = NULL;
    curl_mime *mime = NULL;
    curl_mimepart *part = NULL;
    int unescaped_len = 0;

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create a new MIME structure
    mime = curl_mime_init(NULL);
    if (!mime) {
        goto cleanup;
    }

    // Add a new part to the MIME structure
    part = curl_mime_addpart(mime);
    if (!part) {
        goto cleanup;
    }

    // Unescape the input data
    unescaped_str = curl_easy_unescape(NULL, reinterpret_cast<const char*>(data), size, &unescaped_len);
    if (!unescaped_str) {
        // If unescaping fails, unescaped_len may be undefined, so ensure it's set to 0
        unescaped_len = 0;
        goto cleanup;
    }

    // Ensure unescaped_len is within a reasonable range
    if (unescaped_len < 0 || unescaped_len > 1024) {
        goto cleanup;
    }

    // Set the filename for the MIME part (keeping this as a static value)
    res = curl_mime_filename(part, "input_file");
    if (res != CURLE_OK) {
        goto cleanup;
    }

    // Set the MIME part data with curl_mime_data (since we're not using a file path)
    res = curl_mime_data(part, unescaped_str, CURL_ZERO_TERMINATED);
    if (res != CURLE_OK) {
        goto cleanup;
    }

    // Optionally, set a data callback if needed (this example uses a simple data setter)
    // res = curl_mime_data_cb(part, unescaped_len, NULL, NULL, NULL, NULL);
    // if (res != CURLE_OK) {
    //     goto cleanup;
    // }

cleanup:
    // Free all allocated resources
    safe_free(&unescaped_str);
    safe_mime_free(&mime);
    safe_mimepart_free(&part);

    // Cleanup libcurl
    curl_global_cleanup();

    return 0;
}