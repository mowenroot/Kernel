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
TIFF* createTIFFFromString(const std::string& data) {
    // Create a TIFF object in memory
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = fuzzInputToString(data, size);

    // Create a TIFF object from the fuzz input string
    TIFF* tif = createTIFFFromString(fuzzInput);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint64_t scanlineSize = 0;
    uint32_t row = 0;
    uint16_t sample = 0;
    uint32_t tile = 0;
    tmsize_t tileSize = 0;
    void* buffer = nullptr;

    // Calculate scanline size
    scanlineSize = TIFFScanlineSize64(tif);
    if (scanlineSize == 0) {
        TIFFClose(tif);
        return 0;
    }

    // Allocate buffer for reading/writing scanlines
    buffer = _TIFFmalloc(static_cast<tmsize_t>(scanlineSize));
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }

    // Read a scanline
    if (TIFFReadScanline(tif, buffer, row, sample) < 0) {
        _TIFFfree(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Write a scanline
    if (TIFFWriteScanline(tif, buffer, row, sample) < 0) {
        _TIFFfree(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Read a raw tile
    tileSize = TIFFReadRawTile(tif, tile, buffer, static_cast<tmsize_t>(scanlineSize));
    if (tileSize == static_cast<tmsize_t>(-1)) {
        _TIFFfree(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Flush data to ensure consistency
    if (TIFFFlushData(tif) != 1) {
        _TIFFfree(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated resources
    _TIFFfree(buffer);
    TIFFClose(tif);

    return 0;
}
