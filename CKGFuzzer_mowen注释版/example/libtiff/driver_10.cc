#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream
#include <fcntl.h> // Include for O_RDONLY

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Custom warning handler
static void CustomWarningHandler(thandle_t, const char* module, const char* fmt, va_list ap) {
    // Custom warning handling logic
    // For simplicity, we just print the warning
    vfprintf(stderr, fmt, ap);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Set custom warning handler
    TIFFSetWarningHandlerExt(CustomWarningHandler);

    // Set mode to read
    int oldMode = TIFFSetMode(tif, O_RDONLY);
    if (oldMode == -1) {
        TIFFClose(tif);
        return 0; // Failed to set mode
    }

    // Allocate buffer for raw tile data
    uint32 tile = 0; // Assuming tile index 0 for simplicity
    tmsize_t tileSize = TIFFTileSize(tif);
    if (tileSize == 0) {
        TIFFClose(tif);
        return 0; // Invalid tile size
    }
    uint8_t* tileBuffer = (uint8_t*)malloc(tileSize);
    if (!tileBuffer) {
        TIFFClose(tif);
        return 0; // Memory allocation failed
    }

    // Read raw tile data
    tmsize_t bytesRead = TIFFReadRawTile(tif, tile, tileBuffer, tileSize);
    if (bytesRead == (tmsize_t)(-1)) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0; // Failed to read raw tile
    }

    // Perform byte swapping on the tile data
    TIFFSwabArrayOfLong8((uint64_t*)tileBuffer, bytesRead / sizeof(uint64_t));

    // Get bit reversal table
    const unsigned char* bitRevTable = TIFFGetBitRevTable(1);
    if (!bitRevTable) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0; // Failed to get bit reversal table
    }

    // Clean up
    free(tileBuffer);
    TIFFClose(tif);

    return 0; // Success
}
