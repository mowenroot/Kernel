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

    // Call TIFFNumberOfStrips to get the number of strips
    uint32 nStrips = TIFFNumberOfStrips(tif);
    if (nStrips == 0) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA
    if (!TIFFRGBAImageOK(tif, emsg)) {
        freeTIFF(tif);
        return 0;
    }

    // Allocate memory for tile data
    tileSize = TIFFTileSize(tif);
    if (tileSize == 0) {
        freeTIFF(tif);
        return 0;
    }
    tileData = malloc(tileSize);
    if (!tileData) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFReadRawTile to read raw tile data
    if (TIFFReadRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
        free(tileData);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteRawTile to write raw tile data
    if (TIFFWriteRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
        free(tileData);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFFlushData to flush data to the file
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
