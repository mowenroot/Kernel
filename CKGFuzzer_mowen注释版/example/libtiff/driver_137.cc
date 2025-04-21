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

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
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
    void* buffer = nullptr;
    tmsize_t tileSize = 0;
    tmsize_t tileRowSize = 0;
    uint32 tileIndex = 0;
    uint32 x = 0, y = 0, z = 0;
    uint16 s = 0;

    // Initialize the TIFF object in memory
    tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Calculate tile size
    tileSize = TIFFTileSize(tif);
    if (tileSize <= 0) {
        freeTIFF(tif);
        return 0;
    }

    // Calculate tile row size
    tileRowSize = TIFFTileRowSize(tif);
    if (tileRowSize <= 0) {
        freeTIFF(tif);
        return 0;
    }

    // Allocate buffer for reading tiles
    buffer = malloc(tileSize);
    if (!buffer) {
        freeTIFF(tif);
        return 0;
    }

    // Read raw tile
    tileIndex = 0; // Assuming the first tile for simplicity
    if (TIFFReadRawTile(tif, tileIndex, buffer, tileSize) != tileSize) {
        free(buffer);
        freeTIFF(tif);
        return 0;
    }

    // Read encoded tile
    if (TIFFReadEncodedTile(tif, tileIndex, buffer, tileSize) != tileSize) {
        free(buffer);
        freeTIFF(tif);
        return 0;
    }

    // Read tile
    x = 0; y = 0; z = 0; s = 0; // Assuming default values for simplicity
    if (TIFFReadTile(tif, buffer, x, y, z, s) != tileSize) {
        free(buffer);
        freeTIFF(tif);
        return 0;
    }

    // Write tile (for testing purposes, writing to a file named 'output_file')
    TIFF* outputTif = TIFFOpen("output_file", "w");
    if (outputTif) {
        if (TIFFWriteTile(outputTif, buffer, x, y, z, s) != tileSize) {
            TIFFClose(outputTif);
            free(buffer);
            freeTIFF(tif);
            return 0;
        }
        TIFFClose(outputTif);
    }

    // Free allocated resources
    free(buffer);
    freeTIFF(tif);

    return 0;
}
