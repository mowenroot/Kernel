#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (str == nullptr) {
        return nullptr;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const char* str) {
    std::istringstream s(str); // Use std::istringstream instead of std::string
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (tif == nullptr) {
        return nullptr;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* str = fuzzInputToString(data, size);
    if (str == nullptr) {
        return 0;
    }

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(str);
    if (tif == nullptr) {
        free(str);
        return 0;
    }

    // Variables for API calls
    uint32 tile = 0;
    tmsize_t tileSize = 1024; // Example size, should be derived from fuzz input
    void* buffer = malloc(tileSize);
    if (buffer == nullptr) {
        TIFFClose(tif);
        free(str);
        return 0;
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        // Handle error
    }

    // Call TIFFWriteRawTile
    tmsize_t writeResult = TIFFWriteRawTile(tif, tile, buffer, tileSize);
    if (writeResult == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFReadRawTile
    tmsize_t readResult = TIFFReadRawTile(tif, tile, buffer, tileSize);
    if (readResult == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFRewriteDirectory
    int rewriteResult = TIFFRewriteDirectory(tif);
    if (rewriteResult != 1) {
        // Handle error
    }

    // Clean up
    free(buffer);
    TIFFClose(tif);
    free(str);

    return 0;
}
