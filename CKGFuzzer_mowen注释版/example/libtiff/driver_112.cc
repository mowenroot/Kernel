#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h> // Include for wcslen and wcstombs

// Function to convert fuzz input to a wide character string
wchar_t* fuzzInputToWideChar(const uint8_t* data, size_t size) {
    // Ensure the input size is within a reasonable limit for conversion
    if (size > 1024) {
        size = 1024;
    }

    // Allocate memory for the wide character string
    wchar_t* wstr = (wchar_t*)malloc((size + 1) * sizeof(wchar_t));
    if (!wstr) {
        return NULL;
    }

    // Convert the input data to a wide character string
    for (size_t i = 0; i < size; ++i) {
        wstr[i] = (wchar_t)data[i];
    }
    wstr[size] = L'\0';

    return wstr;
}

// Function to convert fuzz input to a multi-byte string
char* fuzzInputToMultiByte(const uint8_t* data, size_t size) {
    // Ensure the input size is within a reasonable limit for conversion
    if (size > 1024) {
        size = 1024;
    }

    // Allocate memory for the multi-byte string
    char* mbstr = (char*)malloc(size + 1);
    if (!mbstr) {
        return NULL;
    }

    // Copy the input data to the multi-byte string
    memcpy(mbstr, data, size);
    mbstr[size] = '\0';

    return mbstr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a wide character string for TIFFOpenW
    wchar_t* wfilename = fuzzInputToWideChar(data, size);
    if (!wfilename) {
        return 0;
    }

    // Convert wide character string to a narrow character string
    size_t len = wcslen(wfilename);
    char* filename = (char*)malloc((len + 1) * sizeof(char));
    if (!filename) {
        free(wfilename);
        return 0;
    }
    wcstombs(filename, wfilename, len + 1); // Convert wchar_t to char

    // Convert fuzz input to a multi-byte string for mode
    char* mode = fuzzInputToMultiByte(data, size);
    if (!mode) {
        free(filename);
        free(wfilename);
        return 0;
    }

    // Open the TIFF file
    TIFF* tif = TIFFOpen(filename, mode); // Use TIFFOpen instead of TIFFOpenW
    if (!tif) {
        free(filename);
        free(wfilename);
        free(mode);
        return 0;
    }

    // Allocate buffers for reading and writing
    void* readBuffer = malloc(size);
    if (!readBuffer) {
        TIFFClose(tif);
        free(filename);
        free(wfilename);
        free(mode);
        return 0;
    }

    void* writeBuffer = malloc(size);
    if (!writeBuffer) {
        free(readBuffer);
        TIFFClose(tif);
        free(filename);
        free(wfilename);
        free(mode);
        return 0;
    }

    // Setup the read buffer
    if (TIFFReadBufferSetup(tif, readBuffer, size) != 1) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        free(filename);
        free(wfilename);
        free(mode);
        return 0;
    }

    // Read a raw tile
    uint32 tile = 0; // Assuming tile index 0 for simplicity
    tmsize_t tileSize = TIFFReadRawTile(tif, tile, readBuffer, size);
    if (tileSize == (tmsize_t)(-1)) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        free(filename);
        free(wfilename);
        free(mode);
        return 0;
    }

    // Read an encoded strip
    uint32 strip = 0; // Assuming strip index 0 for simplicity
    tmsize_t stripSize = TIFFReadEncodedStrip(tif, strip, readBuffer, size);
    if (stripSize == (tmsize_t)(-1)) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        free(filename);
        free(wfilename);
        free(mode);
        return 0;
    }

    // Write a scanline
    uint32 row = 0; // Assuming row index 0 for simplicity
    uint16 sample = 0; // Assuming sample index 0 for simplicity
    if (TIFFWriteScanline(tif, writeBuffer, row, sample) != 1) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        free(filename);
        free(wfilename);
        free(mode);
        return 0;
    }

    // Clean up
    free(readBuffer);
    free(writeBuffer);
    TIFFClose(tif);
    free(filename);
    free(wfilename);
    free(mode);

    return 0;
}
