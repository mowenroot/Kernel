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

// Function to safely create a curl_slist from fuzz input
struct curl_slist* create_slist(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* header = safe_strndup(data, size);
    if (!header) return nullptr;
    struct curl_slist* slist = curl_slist_append(nullptr, header);
    free(header);
    return slist;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 5) return 0;

    // Initialize curl_mime and curl_mimepart
    curl_mime* mime = curl_mime_init(nullptr);
    if (!mime) return 0;

    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        return 0;
    }

    // Use curl_mime_filedata
    CURLcode filedata_res = curl_mime_filedata(part, "input_file");
    if (filedata_res != CURLE_OK) {
        curl_mime_free(mime);
        return 0;
    }

    // Use curl_mime_headers
    struct curl_slist* headers = create_slist(data, size / 2);
    if (headers) {
        CURLcode headers_res = curl_mime_headers(part, headers, 1);
        if (headers_res != CURLE_OK) {
            curl_slist_free_all(headers);
            curl_mime_free(mime);
            return 0;
        }
    }

    // Use curl_mime_encoder
    char* encoding = safe_strndup(data + size / 2, size / 2);
    if (encoding) {
        CURLcode encoder_res = curl_mime_encoder(part, encoding);
        free(encoding);
        if (encoder_res != CURLE_OK) {
            curl_mime_free(mime);
            return 0;
        }
    }

    // Use curl_mime_subparts
    curl_mime* subparts = curl_mime_init(nullptr);
    if (subparts) {
        CURLcode subparts_res = curl_mime_subparts(part, subparts);
        if (subparts_res != CURLE_OK) {
            curl_mime_free(subparts);
            curl_mime_free(mime);
            return 0;
        }
    }

    // Clean up
    curl_mime_free(mime);
    if (headers) curl_slist_free_all(headers);
    if (subparts) curl_mime_free(subparts);

    return 0;
}
