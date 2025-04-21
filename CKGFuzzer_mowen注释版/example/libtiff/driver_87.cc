#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
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
    // Convert fuzz input to a string
    char* tiffData = fuzzInputToString(data, size);
    if (tiffData == NULL) {
        return 0;
    }

    // Open TIFF stream in memory
    std::istringstream s(tiffData); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (tif == NULL) {
        free(tiffData);
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = 1024; // Arbitrary size for the tile buffer
    void* tileBuffer = malloc(tileSize);
    if (tileBuffer == NULL) {
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t bytesRead = TIFFReadRawTile(tif, tile, tileBuffer, tileSize);
    if (bytesRead == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFFieldWithTag
    uint32 tag = 256; // Example tag, ImageWidth
    const TIFFField* field = TIFFFieldWithTag(tif, tag);
    if (field == NULL) {
        // Handle error
    }

    // Call TIFFSetField
    if (TIFFSetField(tif, tag, 1024) != 1) {
        // Handle error
    }

    // Call TIFFRewriteDirectory
    if (TIFFRewriteDirectory(tif) != 1) {
        // Handle error
    }

    // Call TIFFFreeDirectory
    TIFFFreeDirectory(tif);

    // Clean up
    free(tileBuffer);
    TIFFClose(tif);
    free(tiffData);

    return 0;
}
