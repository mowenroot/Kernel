#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF stream in memory
TIFF* createInMemoryTIFF(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("mem", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF stream in memory
void freeInMemoryTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    void* buffer = nullptr;
    tmsize_t bufferSize = 0;

    // Initialize the TIFF stream in memory
    tif = createInMemoryTIFF(data, size);
    if (!tif) {
        return 0;
    }

    // Determine the size of the TIFF image
    uint32_t width, height;
    if (!TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width) ||
        !TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height)) {
        freeInMemoryTIFF(tif);
        return 0;
    }

    // Allocate a buffer large enough to hold the largest strip or tile
    bufferSize = TIFFStripSize(tif);
    if (bufferSize == 0) {
        bufferSize = TIFFTileSize(tif);
    }
    if (bufferSize == 0) {
        freeInMemoryTIFF(tif);
        return 0;
    }
    buffer = malloc(bufferSize);
    if (!buffer) {
        freeInMemoryTIFF(tif);
        return 0;
    }

    // Call each API at least once
    uint32_t strip = 0;
    uint32_t tile = 0;
    uint32_t row = 0;
    uint32_t x = 0, y = 0, z = 0;
    uint16_t sample = 0;

    // TIFFReadEncodedStrip
    if (TIFFReadEncodedStrip(tif, strip, buffer, bufferSize) == (tmsize_t)(-1)) {
        // Handle error
    }

    // TIFFReadEncodedTile
    if (TIFFReadEncodedTile(tif, tile, buffer, bufferSize) == (tmsize_t)(-1)) {
        // Handle error
    }

    // TIFFReadTile
    if (TIFFReadTile(tif, buffer, x, y, z, sample) == (tmsize_t)(-1)) {
        // Handle error
    }

    // TIFFReadScanline
    if (TIFFReadScanline(tif, buffer, row, sample) == -1) {
        // Handle error
    }

    // TIFFReadRawTile
    if (TIFFReadRawTile(tif, tile, buffer, bufferSize) == (tmsize_t)(-1)) {
        // Handle error
    }

    // TIFFReadRawStrip
    if (TIFFReadRawStrip(tif, strip, buffer, bufferSize) == (tmsize_t)(-1)) {
        // Handle error
    }

    // Free allocated resources
    free(buffer);
    freeInMemoryTIFF(tif);

    return 0;
}
