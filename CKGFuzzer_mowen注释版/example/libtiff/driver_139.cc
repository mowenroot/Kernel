#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const std::string& input) {
    // Create a TIFF object in memory
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(input);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = TIFFTileSize(tif);
    if (tileSize == 0) {
        TIFFClose(tif);
        return 0;
    }

    // Allocate buffers
    void* writeBuffer = malloc(tileSize);
    void* readBuffer = malloc(tileSize);
    if (!writeBuffer || !readBuffer) {
        free(writeBuffer);
        free(readBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Initialize write buffer with fuzz input data
    memcpy(writeBuffer, data, size < tileSize ? size : tileSize);

    // Call TIFFWriteEncodedTile
    tmsize_t written = TIFFWriteEncodedTile(tif, tile, writeBuffer, tileSize);
    if (written == (tmsize_t)(-1)) {
        free(writeBuffer);
        free(readBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFFlush
    if (!TIFFFlush(tif)) {
        free(writeBuffer);
        free(readBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadEncodedTile
    tmsize_t read = TIFFReadEncodedTile(tif, tile, readBuffer, tileSize);
    if (read == (tmsize_t)(-1)) {
        free(writeBuffer);
        free(readBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReverseBits
    TIFFReverseBits(static_cast<uint8_t*>(readBuffer), read);

    // Call TIFFSwabArrayOfShort
    TIFFSwabArrayOfShort(static_cast<uint16_t*>(readBuffer), read / sizeof(uint16_t));

    // Free allocated resources
    free(writeBuffer);
    free(readBuffer);
    TIFFClose(tif);

    return 0;
}
