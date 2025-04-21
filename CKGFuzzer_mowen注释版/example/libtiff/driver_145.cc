#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)_TIFFmalloc(size + 1);
    if (!str) return nullptr;
    _TIFFmemcpy(str, data, size);
    str[size] = '\0'; // Null-terminate the string
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size < 1) return 0;

    // Convert fuzz input to a string
    char* inputStr = fuzzInputToString(data, size);
    if (!inputStr) return 0;

    // Allocate memory for a buffer
    tmsize_t bufferSize = size * 2; // Example size, can be adjusted
    void* buffer = _TIFFmalloc(bufferSize);
    if (!buffer) {
        _TIFFfree(inputStr);
        return 0;
    }

    // Initialize the buffer with a value
    _TIFFmemset(buffer, 0xAA, bufferSize);

    // Copy part of the input string to the buffer
    tmsize_t copySize = (size < bufferSize) ? size : bufferSize;
    _TIFFmemcpy(buffer, inputStr, copySize);

    // Reallocate the buffer to a smaller size
    tmsize_t newBufferSize = bufferSize / 2;
    void* newBuffer = _TIFFrealloc(buffer, newBufferSize);
    if (!newBuffer) {
        _TIFFfree(buffer);
        _TIFFfree(inputStr);
        return 0;
    }

    // Free the reallocated buffer
    _TIFFfree(newBuffer);

    // Free the input string
    _TIFFfree(inputStr);

    return 0;
}
