#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to free allocated memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 16) return 0;

    // Convert fuzz input to a string for TIFFOpen
    char* tiffFileName = fuzzInputToString(data, size);
    if (!tiffFileName) return 0;

    // Open the TIFF file
    TIFF* tif = TIFFOpen(tiffFileName, "r");
    if (!tif) {
        safeFree(tiffFileName);
        return 0;
    }

    // Allocate buffer for reading the strip
    uint32 strip = 0; // Assuming strip 0 for simplicity
    tmsize_t stripSize = TIFFStripSize(tif);
    if (stripSize <= 0) {
        TIFFClose(tif);
        safeFree(tiffFileName);
        return 0;
    }
    uint8_t* stripBuffer = (uint8_t*)malloc(stripSize);
    if (!stripBuffer) {
        TIFFClose(tif);
        safeFree(tiffFileName);
        return 0;
    }

    // Read the encoded strip
    tmsize_t readSize = TIFFReadEncodedStrip(tif, strip, stripBuffer, stripSize);
    if (readSize == (tmsize_t)(-1)) {
        free(stripBuffer);
        TIFFClose(tif);
        safeFree(tiffFileName);
        return 0;
    }

    // Reverse the bits in the strip buffer
    TIFFReverseBits(stripBuffer, readSize);

    // Allocate memory for the array of long8
    uint64_t* long8Array = (uint64_t*)malloc(readSize);
    if (!long8Array) {
        free(stripBuffer);
        TIFFClose(tif);
        safeFree(tiffFileName);
        return 0;
    }

    // Copy the strip buffer to the long8 array
    memcpy(long8Array, stripBuffer, readSize);

    // Reverse the byte order of the long8 array
    TIFFSwabArrayOfLong8(long8Array, readSize / sizeof(uint64_t));

    // Clean up
    free(long8Array);
    free(stripBuffer);
    TIFFClose(tif);
    safeFree(tiffFileName);

    return 0;
}
