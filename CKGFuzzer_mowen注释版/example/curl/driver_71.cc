#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely format a string from fuzz input
char* safe_format_string(const uint8_t* data, size_t size) {
    if (size == 0) return NULL;
    char* format = (char*)malloc(size + 1);
    if (!format) return NULL;
    memcpy(format, data, size);
    format[size] = '\0';
    return format;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) return 0;

    // Initialize variables
    CURL* easy = curl_easy_init();
    if (!easy) return 0;

    // Initialize MIME structure
    curl_mime* mime = curl_mime_init(easy);
    if (!mime) {
        curl_easy_cleanup(easy);
        return 0;
    }

    // Add a part to the MIME structure
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Safely extract format strings from fuzz input
    char* format1 = safe_format_string(data, size / 2);
    char* format2 = safe_format_string(data + (size / 2), size - (size / 2));
    if (!format1 || !format2) {
        free(format1);
        free(format2);
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Use curl_mprintf to print to stdout
    int ret_mprintf = curl_mprintf(format1);
    if (ret_mprintf < 0) {
        free(format1);
        free(format2);
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Use curl_msnprintf to format a string into a buffer
    char buffer[256];
    int ret_msnprintf = curl_msnprintf(buffer, sizeof(buffer), format2);
    if (ret_msnprintf < 0) {
        free(format1);
        free(format2);
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Use curl_mvaprintf to dynamically format a string
    // NOTE: Removed va_start and va_end as they are not needed here
    char* dynamic_str = curl_mvaprintf(format2, nullptr);
    if (!dynamic_str) {
        free(format1);
        free(format2);
        curl_mime_free(mime);
        curl_easy_cleanup(easy);
        return 0;
    }

    // Use curl_mfprintf to print to a file
    FILE* output_file = fopen("output_file", "w");
    if (output_file) {
        int ret_mfprintf = curl_mfprintf(output_file, "%s", dynamic_str);
        if (ret_mfprintf < 0) {
            free(format1);
            free(format2);
            free(dynamic_str);
            curl_mime_free(mime);
            curl_easy_cleanup(easy);
            fclose(output_file);
            return 0;
        }
        fclose(output_file);
    }

    // Clean up resources
    free(format1);
    free(format2);
    free(dynamic_str);
    curl_mime_free(mime);
    curl_easy_cleanup(easy);

    return 0;
}
