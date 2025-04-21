#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from the fuzz input
TIFF* CreateTIFFInMemory(const uint8_t* data, size_t size) {
    std::string inputStr = FuzzInputToString(data, size);
    std::istringstream s(inputStr); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < 8) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = CreateTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void* tileData = nullptr;
    int result = 0;

    // Extract tile index and size from the fuzz input
    tile = *reinterpret_cast<const uint32_t*>(data);
    tileSize = *reinterpret_cast<const tmsize_t*>(data + 4);

    // Allocate memory for tile data
    tileData = malloc(tileSize);
    if (!tileData) {
        TIFFClose(tif);
        return 0;
    }

    // Set a TIFF field using TIFFSetField
    result = TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 1024);
    if (result != 1) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Write raw tile data using TIFFWriteRawTile
    result = TIFFWriteRawTile(tif, tile, tileData, tileSize);
    if (result == (tmsize_t)(-1)) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Flush data to ensure consistency
    result = TIFFFlushData(tif);
    if (result != 1) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Read raw tile data using TIFFReadRawTile
    result = TIFFReadRawTile(tif, tile, tileData, tileSize);
    if (result == (tmsize_t)(-1)) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated memory and close the TIFF object
    free(tileData);
    TIFFClose(tif);

    return 0;
}
