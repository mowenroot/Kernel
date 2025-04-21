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

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size < 1 || size > 1024) {
        return 0;
    }

    // Initialize variables
    CURL* curl = curl_easy_init();
    if (!curl) {
        return 0;
    }

    // Initialize MIME structure
    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Add a part to the MIME structure
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a form and add parts to it
    struct curl_httppost* form = nullptr;
    struct curl_httppost* last_post = nullptr;
    CURLFORMcode form_add_result = curl_formadd(&form, &last_post,
                                                CURLFORM_COPYNAME, "name",
                                                CURLFORM_COPYCONTENTS, "value",
                                                CURLFORM_END);
    if (form_add_result != CURL_FORMADD_OK) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Safely copy the input data to a string
    char* input_str = safe_strndup(data, size);
    if (!input_str) {
        curl_formfree(form);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Use the input string in the form
    CURLFORMcode form_add_result2 = curl_formadd(&form, &last_post,
                                                 CURLFORM_COPYNAME, "input",
                                                 CURLFORM_COPYCONTENTS, input_str,
                                                 CURLFORM_END);
    free(input_str);
    if (form_add_result2 != CURL_FORMADD_OK) {
        curl_formfree(form);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Free the form
    curl_formfree(form);

    // Free the MIME structure
    curl_mime_free(mime);

    // Clean up the CURL handle
    curl_easy_cleanup(curl);

    return 0;
}
