#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Custom error handler function
static void customErrorHandler(thandle_t, const char* module, const char* fmt, va_list ap) {
    // Custom error handling logic can be added here
    vfprintf(stderr, fmt, ap);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    TIFF *tif = nullptr;
    char emsg[1024] = {0};
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void *tileData = nullptr;

    // Set custom error handler
    TIFFSetErrorHandlerExt(customErrorHandler);

    // Convert fuzz input to a string
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));

    // Create a TIFF object in memory
    tif = TIFFStreamOpen("mem", &s);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Check if the TIFF image can be converted to RGBA format
    if (!TIFFRGBAImageOK(tif, emsg)) {
        TIFFClose(tif);
        return 0; // Image cannot be converted to RGBA format
    }

    // Read raw tile data
    tile = 0; // Assuming tile index 0 for simplicity
    tileSize = TIFFReadRawTile(tif, tile, nullptr, 0);
    if (tileSize == (tmsize_t)(-1)) {
        TIFFClose(tif);
        return 0; // Failed to read raw tile data
    }

    // Allocate memory for tile data
    tileData = malloc(tileSize);
    if (!tileData) {
        TIFFClose(tif);
        return 0; // Memory allocation failed
    }

    // Read raw tile data into allocated buffer
    if (TIFFReadRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
        free(tileData);
        TIFFClose(tif);
        return 0; // Failed to read raw tile data
    }

    // Write raw tile data back to the TIFF file
    if (TIFFWriteRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
        free(tileData);
        TIFFClose(tif);
        return 0; // Failed to write raw tile data
    }

    // Flush the TIFF file to ensure all data is written
    if (!TIFFFlush(tif)) {
        free(tileData);
        TIFFClose(tif);
        return 0; // Failed to flush TIFF file
    }

    // Free allocated resources
    free(tileData);
    TIFFClose(tif);

    return 0; // Success
}
