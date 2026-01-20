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
    char emsg[1024];
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void* tileData = nullptr;

    // Initialize the TIFF object in memory
    tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Set a field using TIFFSetField
    if (!TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 1024)) {
        freeTIFF(tif);
        return 0;
    }

    // Check if the TIFF image can be converted to RGBA format
    if (!TIFFRGBAImageOK(tif, emsg)) {
        freeTIFF(tif);
        return 0;
    }

    // Read raw tile data
    tile = 0; // Assuming tile 0 for simplicity
    tileSize = TIFFTileSize(tif);
    if (tileSize <= 0) {
        freeTIFF(tif);
        return 0;
    }

    tileData = malloc(tileSize);
    if (!tileData) {
        freeTIFF(tif);
        return 0;
    }

    if (TIFFReadRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
        free(tileData);
        freeTIFF(tif);
        return 0;
    }

    // Write encoded tile data
    if (TIFFWriteEncodedTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
        free(tileData);
        freeTIFF(tif);
        return 0;
    }

    // Flush data to ensure consistency
    if (TIFFFlushData(tif) == 0) {
        free(tileData);
        freeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    free(tileData);
    freeTIFF(tif);

    return 0;
}
