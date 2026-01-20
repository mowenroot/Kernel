#include <tiffio.h>
#include <tiffio.hxx>
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

// Function to safely convert fuzz input to a string
char* fuzz_input_to_string(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    char* module = nullptr;
    char* fmt = nullptr;
    char* warning_msg = nullptr;
    char* error_msg = nullptr;
    TIFFErrorHandler prev_warning_handler = nullptr;
    TIFFErrorHandlerExt prev_warning_handler_ext = nullptr;

    // Allocate memory for module and format strings
    module = safe_strndup(data, 8);
    fmt = safe_strndup(data + 8, 8);
    if (!module || !fmt) goto cleanup;

    // Set custom warning handlers
    prev_warning_handler = TIFFSetWarningHandler(nullptr);
    prev_warning_handler_ext = TIFFSetWarningHandlerExt(nullptr);

    // Generate warning and error messages
    warning_msg = fuzz_input_to_string(data + 16, size - 16);
    error_msg = fuzz_input_to_string(data + 16, size - 16);
    if (!warning_msg || !error_msg) goto cleanup;

    // Call TIFFWarning and TIFFWarningExt
    TIFFWarning(module, fmt, warning_msg);
    TIFFWarningExt(0, module, fmt, warning_msg);

    // Call TIFFError and TIFFErrorExt
    TIFFError(module, fmt, error_msg);
    TIFFErrorExt(0, module, fmt, error_msg);

cleanup:
    // Restore previous warning handlers
    TIFFSetWarningHandler(prev_warning_handler);
    TIFFSetWarningHandlerExt(prev_warning_handler_ext);

    // Free allocated memory
    free(module);
    free(fmt);
    free(warning_msg);
    free(error_msg);

    return 0;
}
