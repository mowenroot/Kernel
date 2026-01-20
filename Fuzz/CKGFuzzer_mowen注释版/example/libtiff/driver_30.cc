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

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("memory", &s);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzData = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzData);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void* tileBuffer = nullptr;
    int result = 0;

    // Call TIFFTileSize to get the tile size
    tileSize = TIFFTileSize(tif);
    if (tileSize <= 0) {
        TIFFClose(tif);
        return 0; // Invalid tile size
    }

    // Allocate memory for the tile buffer
    tileBuffer = malloc(tileSize);
    if (!tileBuffer) {
        TIFFClose(tif);
        return 0; // Memory allocation failed
    }

    // Call TIFFWriteEncodedTile to write encoded tile data
    result = TIFFWriteEncodedTile(tif, tile, tileBuffer, tileSize);
    if (result == (tmsize_t)(-1)) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0; // Write operation failed
    }

    // Call TIFFReadRawTile to read raw tile data
    result = TIFFReadRawTile(tif, tile, tileBuffer, tileSize);
    if (result == (tmsize_t)(-1)) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0; // Read operation failed
    }

    // Call TIFFUnlinkDirectory to unlink a directory
    uint16 dirn = 1; // Example directory number
    result = TIFFUnlinkDirectory(tif, dirn);
    if (result == 0) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0; // Unlink operation failed
    }

    // Call TIFFReadCustomDirectory to read a custom directory
    toff_t diroff = 0; // Example directory offset
    const TIFFFieldArray* infoarray = nullptr; // Example field array
    result = TIFFReadCustomDirectory(tif, diroff, infoarray);
    if (result == 0) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0; // Read custom directory operation failed
    }

    // Free allocated resources
    free(tileBuffer);
    TIFFClose(tif);

    return 0; // Success
}
