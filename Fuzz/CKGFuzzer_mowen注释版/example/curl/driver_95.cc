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

// Function to safely create a curl_mimepart
curl_mimepart* safe_mimepart_create() {
    CURL* curl = curl_easy_init();
    if (!curl) return nullptr;

    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return nullptr;
    }

    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return nullptr;
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    return part;
}

// Function to safely create a curl_mime
curl_mime* safe_mime_create() {
    CURL* curl = curl_easy_init();
    if (!curl) return nullptr;

    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return nullptr;
    }

    curl_easy_cleanup(curl);
    return mime;
}

// Function to safely create a CURL handle
CURL* safe_curl_easy_init() {
    CURL* easy = curl_easy_init();
    if (!easy) return nullptr;
    return easy;
}

// Function to safely create a curl_pushheaders
curl_pushheaders* safe_pushheaders_create() {
    CURL* curl = curl_easy_init();
    if (!curl) return nullptr;

    // Use curl_pushheader_bynum to get a header by number
    char* header = curl_pushheader_bynum(nullptr, 0);
    if (!header) {
        curl_easy_cleanup(curl);
        return nullptr;
    }

    curl_easy_cleanup(curl);
    return nullptr; // Return nullptr since curl_pushheaders is not directly creatable
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

    // Initialize variables
    CURL* easy = nullptr;
    curl_mimepart* part = nullptr;
    curl_mime* mime = nullptr;
    curl_pushheaders* headers = nullptr;
    char* mimetype = nullptr;
    char* header_name = nullptr;
    CURLcode res;

    // Initialize CURL handle
    easy = safe_curl_easy_init();
    if (!easy) goto cleanup;

    // Initialize curl_mimepart
    part = safe_mimepart_create();
    if (!part) goto cleanup;

    // Initialize curl_mime
    mime = safe_mime_create();
    if (!mime) goto cleanup;

    // Initialize curl_pushheaders
    headers = safe_pushheaders_create();
    if (!headers) goto cleanup;

    // Set MIME type
    mimetype = safe_strndup(data, size / 2);
    if (!mimetype) goto cleanup;
    res = curl_mime_type(part, mimetype);
    if (res != CURLE_OK) goto cleanup;

    // Set subparts
    res = curl_mime_subparts(part, mime);
    if (res != CURLE_OK) goto cleanup;

    // Get next header (dummy call)
    curl_easy_nextheader(easy, 0, 0, nullptr);

    // Get WebSocket meta (dummy call)
    curl_ws_meta(nullptr);

    // Get push header by name
    header_name = safe_strndup(data + size / 2, size - size / 2);
    if (!header_name) goto cleanup;
    curl_pushheader_byname(nullptr, header_name); // Use nullptr for curl_pushheaders

cleanup:
    // Free allocated resources
    free(mimetype);
    free(header_name);
    if (mime) curl_mime_free(mime);
    if (easy) curl_easy_cleanup(easy);

    return 0;
}
