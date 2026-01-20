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

// Custom warning handler
void customWarningHandler(const char* module, const char* fmt, va_list ap) {
    // Custom warning handling logic can be added here
    vfprintf(stderr, fmt, ap);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    char emsg[1024] = {0};
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void* tileData = nullptr;

    // Set custom warning handler
    TIFFSetWarningHandler(customWarningHandler);

    // Check if TIFF image can be converted to RGBA format
    if (TIFFRGBAImageOK(tif, emsg)) {
        // Allocate memory for tile data
        tileSize = TIFFTileSize(tif);
        if (tileSize > 0) {
            tileData = malloc(tileSize);
            if (!tileData) {
                TIFFClose(tif);
                return 0; // Memory allocation failed
            }

            // Read raw tile data
            if (TIFFReadRawTile(tif, tile, tileData, tileSize) != (tmsize_t)(-1)) {
                // Write raw tile data back to the TIFF
                if (TIFFWriteRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
                    // Handle write error
                }
            } else {
                // Handle read error
            }

            // Free allocated memory
            free(tileData);
        }
    } else {
        // Handle RGBA conversion error
    }

    // Flush data to ensure consistency
    TIFFFlushData(tif);

    // Close TIFF object
    TIFFClose(tif);

    return 0; // Return 0 to indicate success
}
