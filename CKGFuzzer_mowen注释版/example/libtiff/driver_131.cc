#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::stringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const std::string& input) {
    std::istringstream ss(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("MemTIFF", &ss); // Pass the address of the istringstream
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(input);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Variables for API calls
    uint32 tile = 0;
    uint32 row = 0;
    uint32* raster = nullptr;
    tmsize_t tileSize = 0;
    void* tileBuffer = nullptr;

    // Initialize variables to avoid undefined behavior
    tile = static_cast<uint32>(data[0]);
    row = static_cast<uint32>(data[1]);
    tileSize = static_cast<tmsize_t>(data[2]);

    // Allocate memory for tile buffer
    tileBuffer = malloc(tileSize);
    if (!tileBuffer) {
        TIFFClose(tif);
        return 0; // Memory allocation failed
    }

    // Allocate memory for raster
    raster = static_cast<uint32*>(malloc(tileSize * sizeof(uint32)));
    if (!raster) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0; // Memory allocation failed
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        // Handle error
        free(tileBuffer);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteRawTile
    if (TIFFWriteRawTile(tif, tile, tileBuffer, tileSize) == static_cast<tmsize_t>(-1)) {
        // Handle error
        free(tileBuffer);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    if (TIFFReadRawTile(tif, tile, tileBuffer, tileSize) == static_cast<tmsize_t>(-1)) {
        // Handle error
        free(tileBuffer);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFRewriteDirectory
    if (TIFFRewriteDirectory(tif) != 1) {
        // Handle error
        free(tileBuffer);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRGBAStripExt
    if (TIFFReadRGBAStripExt(tif, row, raster, 1) != 1) {
        // Handle error
        free(tileBuffer);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated resources
    free(tileBuffer);
    free(raster);
    TIFFClose(tif);

    return 0; // Success
}
