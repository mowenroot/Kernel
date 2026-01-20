#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    char emsg[1024] = {0};
    uint32_t tile = 0;
    uint32_t row = 0;
    uint32_t* raster = nullptr;
    void* rawTileData = nullptr;
    tmsize_t rawTileSize = 0;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32_t) * 2) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize variables from the fuzz input
    tile = *((uint32_t*)data);
    row = *((uint32_t*)(data + sizeof(uint32_t)));

    // Check if the TIFF image can be converted to RGBA format
    if (TIFFRGBAImageOK(tif, emsg)) {
        // Allocate memory for the raster buffer
        raster = (uint32_t*)malloc(size);
        if (!raster) {
            freeTIFF(tif);
            return 0;
        }

        // Read an RGBA strip from the TIFF image
        if (TIFFReadRGBAStrip(tif, row, raster) != 1) {
            free(raster);
            freeTIFF(tif);
            return 0;
        }

        // Free the raster buffer
        free(raster);
    }

    // Allocate memory for raw tile data
    rawTileData = malloc(size);
    if (!rawTileData) {
        freeTIFF(tif);
        return 0;
    }

    // Read raw tile data from the TIFF image
    rawTileSize = TIFFReadRawTile(tif, tile, rawTileData, size);
    if (rawTileSize == (tmsize_t)(-1)) {
        free(rawTileData);
        freeTIFF(tif);
        return 0;
    }

    // Write raw tile data back to the TIFF image
    if (TIFFWriteRawTile(tif, tile, rawTileData, rawTileSize) != rawTileSize) {
        free(rawTileData);
        freeTIFF(tif);
        return 0;
    }

    // Flush data to ensure consistency
    if (TIFFFlushData(tif) != 1) {
        free(rawTileData);
        freeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    free(rawTileData);
    freeTIFF(tif);

    return 0;
}
