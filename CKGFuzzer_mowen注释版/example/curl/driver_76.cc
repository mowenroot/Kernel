#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to read data from the fuzzer input
static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp) {
    const uint8_t *data = (const uint8_t *)userp;
    size_t data_size = size * nmemb;
    if (data_size > 0) {
        memcpy(ptr, data, data_size);
    }
    return data_size;
}

// Function to seek within the fuzzer input (not implemented)
static int seek_callback(void *userp, curl_off_t offset, int origin) {
    (void)userp;
    (void)offset;
    (void)origin;
    return CURL_SEEKFUNC_CANTSEEK;
}

// Function to free the fuzzer input (not implemented)
static void free_callback(void *userp) {
    (void)userp;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize a CURL handle
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Initialize a MIME handle
    curl_mime *mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a MIME part
    curl_mimepart *part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set the filename for the MIME part
    CURLcode res = curl_mime_filename(part, "input_file");
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Set the data callback for the MIME part
    res = curl_mime_data_cb(part, size, read_callback, seek_callback, free_callback, (void *)data);
    if (res != CURLE_OK) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a subpart MIME handle
    curl_mime *subparts = curl_mime_init(curl);
    if (!subparts) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Associate subparts with the main MIME part
    res = curl_mime_subparts(part, subparts);
    if (res != CURLE_OK) {
        curl_mime_free(subparts);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Free the subparts MIME handle
    curl_mime_free(subparts);

    // Free the main MIME handle
    curl_mime_free(mime);

    // Cleanup the CURL handle
    curl_easy_cleanup(curl);

    return 0;
}
