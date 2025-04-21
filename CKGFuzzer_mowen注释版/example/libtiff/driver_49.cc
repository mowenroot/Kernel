#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const char* data) {
    std::istringstream s(data); // Use std::istringstream instead of std::string
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        fprintf(stderr, "Failed to create TIFF object in memory\n");
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* inputStr = fuzzInputToString(data, size);
    if (!inputStr) return 0;

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(inputStr);
    if (!tif) {
        free(inputStr);
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = 1024; // Example size, should be derived from input
    void* buffer = malloc(tileSize);
    if (!buffer) {
        TIFFClose(tif);
        free(inputStr);
        return 0;
    }

    // Example usage of APIs
    int result = 0;

    // TIFFSetField
    result = TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 100);
    if (result != 1) {
        fprintf(stderr, "TIFFSetField failed\n");
    }

    // TIFFWriteRawTile
    result = TIFFWriteRawTile(tif, tile, buffer, tileSize);
    if (result == (tmsize_t)(-1)) {
        fprintf(stderr, "TIFFWriteRawTile failed\n");
    }

    // TIFFReadRawTile
    result = TIFFReadRawTile(tif, tile, buffer, tileSize);
    if (result == (tmsize_t)(-1)) {
        fprintf(stderr, "TIFFReadRawTile failed\n");
    }

    // TIFFUnlinkDirectory
    result = TIFFUnlinkDirectory(tif, 1);
    if (result != 1) {
        fprintf(stderr, "TIFFUnlinkDirectory failed\n");
    }

    // TIFFFlushData
    result = TIFFFlushData(tif);
    if (result != 1) {
        fprintf(stderr, "TIFFFlushData failed\n");
    }

    // Clean up
    free(buffer);
    TIFFClose(tif);
    free(inputStr);

    return 0;
}
