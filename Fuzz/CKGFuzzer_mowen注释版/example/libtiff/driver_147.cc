#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzz input to a C-string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 1) {
        return 0;
    }

    // Convert fuzz input to a C-string
    char* inputStr = fuzzInputToString(data, size);
    if (inputStr == NULL) {
        return 0;
    }

    // Initialize variables
    TIFFRGBAImage img;
    memset(&img, 0, sizeof(img));

    // Set custom error and warning handlers
    TIFFErrorHandler prevErrorHandler = TIFFSetErrorHandler(NULL);
    TIFFErrorHandler prevWarningHandler = TIFFSetWarningHandler(NULL);

    // Example usage of TIFFErrorExt and TIFFWarningExt
    TIFFErrorExt(0, "ModuleName", "Error message: %s", inputStr);
    TIFFWarningExt(0, "ModuleName", "Warning message: %s", inputStr);

    // Clean up resources
    TIFFRGBAImageEnd(&img);

    // Restore previous error and warning handlers
    TIFFSetErrorHandler(prevErrorHandler);
    TIFFSetWarningHandler(prevWarningHandler);

    // Free allocated memory
    free(inputStr);

    return 0;
}
