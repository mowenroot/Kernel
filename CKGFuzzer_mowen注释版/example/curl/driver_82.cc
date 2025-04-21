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

// Function to safely allocate memory for a string
char* safe_malloc_string(size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memset(str, 0, size + 1);
    return str;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) free(ptr);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size < 1) return 0;

    // Initialize variables
    CURLcode res;
    curl_mime* mime = curl_mime_init(nullptr); // Initialize a curl_mime handle
    if (!mime) return 0;

    curl_mimepart* part = curl_mime_addpart(mime); // Use curl_mime_addpart with the mime handle
    if (!part) {
        curl_mime_free(mime); // Free the mime handle if part creation fails
        return 0;
    }

    // Extract filename from fuzz input
    size_t filename_size = size / 2;
    if (filename_size > 0) {
        char* filename = safe_strndup(data, filename_size);
        if (filename) {
            // Call curl_mime_filename
            res = curl_mime_filename(part, filename);
            if (res != CURLE_OK) {
                safe_free(filename);
                curl_mime_free(mime); // Free the mime handle
                return 0;
            }
            safe_free(filename);
        }
    }

    // Extract filedata from fuzz input
    size_t filedata_size = size - filename_size;
    if (filedata_size > 0) {
        char* filedata = safe_strndup(data + filename_size, filedata_size);
        if (filedata) {
            // Call curl_mime_filedata
            res = curl_mime_filedata(part, filedata);
            if (res != CURLE_OK) {
                safe_free(filedata);
                curl_mime_free(mime); // Free the mime handle
                return 0;
            }
            safe_free(filedata);
        }
    }

    // Extract header from fuzz input
    size_t header_size = size / 4;
    if (header_size > 0) {
        char* header = safe_strndup(data, header_size);
        if (header) {
            // Call curl_pushheader_byname
            char* push_header = curl_pushheader_byname(nullptr, header);
            if (push_header) {
                safe_free(push_header);
            }
            safe_free(header);
        }
    }

    // Call curl_mime_data_cb with dummy callbacks
    res = curl_mime_data_cb(part, filedata_size, nullptr, nullptr, nullptr, nullptr);
    if (res != CURLE_OK) {
        curl_mime_free(mime); // Free the mime handle
        return 0;
    }

    // Call curl_mprintf with a format string derived from fuzz input
    char* format = safe_malloc_string(size);
    if (format) {
        memcpy(format, data, size);
        int print_res = curl_mprintf(format, 42); // Dummy argument
        if (print_res < 0) {
            safe_free(format);
            curl_mime_free(mime); // Free the mime handle
            return 0;
        }
        safe_free(format);
    }

    // Clean up
    curl_mime_free(mime); // Free the mime handle
    return 0;
}
