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

// Function to safely free a string
void safe_free(void* ptr) {
    if (ptr) free(ptr);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size < 1 || size > 1024) return 0;

    // Initialize variables
    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    curl_mime* mime = curl_mime_init(curl);
    if (!mime) {
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a new MIME part
    curl_mimepart* part = curl_mime_addpart(mime);
    if (!part) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Safely copy the input data to a string
    char* input_str = safe_strndup(data, size);
    if (!input_str) {
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a linked list for form data
    struct curl_slist* form_list = nullptr;
    form_list = curl_slist_append(form_list, input_str);
    if (!form_list) {
        safe_free(input_str);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Create a form post
    struct curl_httppost* formpost = nullptr;
    struct curl_httppost* last_post = nullptr;
    CURLFORMcode formadd_result = curl_formadd(&formpost, &last_post,
                                               CURLFORM_COPYNAME, "input_file",
                                               CURLFORM_FILE, input_str,
                                               CURLFORM_END);
    if (formadd_result != CURL_FORMADD_OK) {
        curl_slist_free_all(form_list);
        safe_free(input_str);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Attempt to get form data (placeholder function)
    int formget_result = curl_formget(formpost, nullptr, nullptr);
    if (formget_result != CURL_FORMADD_OK) {
        curl_formfree(formpost);
        curl_slist_free_all(form_list);
        safe_free(input_str);
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Clean up resources
    curl_formfree(formpost);
    curl_slist_free_all(form_list);
    safe_free(input_str);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    return 0;
}
