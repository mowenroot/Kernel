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

// Function to create a TIFF object in memory from a string
TIFF* CreateTIFFInMemory(const std::string& data) {
    // Create a TIFF object in memory
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated resources
void FreeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Variables for API inputs
    uint32_t tile = 0;
    tmsize_t tileSize = 0;
    void* buffer = nullptr;

    // Extract inputs from fuzz data
    if (size >= sizeof(uint32_t)) {
        tile = *reinterpret_cast<const uint32_t*>(data);
    }
    if (size >= sizeof(tmsize_t)) {
        tileSize = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32_t));
    }

    // Allocate buffer for raw tile data
    buffer = malloc(tileSize);
    if (!buffer) {
        FreeTIFF(tif);
        return 0; // Failed to allocate buffer
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to flush data
    }

    // Call TIFFWriteRawTile
    tmsize_t writeResult = TIFFWriteRawTile(tif, tile, buffer, tileSize);
    if (writeResult == (tmsize_t)(-1)) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to write raw tile
    }

    // Call TIFFReadRawTile
    tmsize_t readResult = TIFFReadRawTile(tif, tile, buffer, tileSize);
    if (readResult == (tmsize_t)(-1)) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to read raw tile
    }

    // Call TIFFRewriteDirectory
    int rewriteResult = TIFFRewriteDirectory(tif);
    if (rewriteResult != 1) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to rewrite directory
    }

    // Call TIFFVTileSize
    tmsize_t vTileSizeResult = TIFFVTileSize(tif, tile);
    if (vTileSizeResult == 0) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to calculate vertical tile size
    }

    // Free allocated resources
    free(buffer);
    FreeTIFF(tif);

    return 0; // Success
}
