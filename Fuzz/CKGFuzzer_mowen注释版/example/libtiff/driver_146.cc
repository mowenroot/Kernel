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
    // Ensure we have enough data for at least one API call
    if (size < 1) return 0;

    // Initialize variables
    const char* module = "FuzzTestModule";
    char* message = nullptr;
    char* extended_message = nullptr;
    TIFFErrorHandler prev_error_handler = nullptr;
    TIFFErrorHandler prev_warning_handler = nullptr;

    // Allocate memory for messages
    message = safe_strndup(data, size / 2);
    extended_message = safe_strndup(data + (size / 2), size - (size / 2));

    // Set custom error and warning handlers
    prev_error_handler = TIFFSetErrorHandler(nullptr);
    prev_warning_handler = TIFFSetWarningHandler(nullptr);

    // Call TIFFError and TIFFErrorExt
    if (message) {
        TIFFError(module, "%s", message);
        if (extended_message) {
            TIFFErrorExt(0, module, "%s", extended_message);
        }
    }

    // Call TIFFWarning and TIFFWarningExt
    if (message) {
        TIFFWarning(module, "%s", message);
        if (extended_message) {
            TIFFWarningExt(0, module, "%s", extended_message);
        }
    }

    // Restore previous error and warning handlers
    TIFFSetErrorHandler(prev_error_handler);
    TIFFSetWarningHandler(prev_warning_handler);

    // Free allocated memory
    free(message);
    free(extended_message);

    return 0;
}
