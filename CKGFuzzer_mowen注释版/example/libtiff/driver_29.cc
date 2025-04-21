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
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Function to free the TIFF object and associated memory
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(input);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    uint64 tileRowSize = 0;
    uint16 dirn = 0;
    void* buf = nullptr;

    // Set a field in the TIFF object
    if (TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 1024) != 1) {
        freeTIFF(tif);
        return 0; // Failed to set field
    }

    // Calculate the tile row size
    tileRowSize = TIFFTileRowSize64(tif);
    if (tileRowSize == 0) {
        freeTIFF(tif);
        return 0; // Failed to calculate tile row size
    }

    // Allocate buffer for reading tiles
    tileSize = static_cast<tmsize_t>(tileRowSize);
    buf = malloc(tileSize);
    if (!buf) {
        freeTIFF(tif);
        return 0; // Failed to allocate buffer
    }

    // Read raw tile data
    if (TIFFReadRawTile(tif, tile, buf, tileSize) == (tmsize_t)(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to read raw tile
    }

    // Read encoded tile data
    if (TIFFReadEncodedTile(tif, tile, buf, tileSize) == (tmsize_t)(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to read encoded tile
    }

    // Unlink a directory
    if (TIFFUnlinkDirectory(tif, dirn) != 1) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to unlink directory
    }

    // Free allocated resources
    free(buf);
    freeTIFF(tif);

    return 0; // Success
}
