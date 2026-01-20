#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Custom error handler function
static void CustomErrorHandler(thandle_t, const char* module, const char* fmt, va_list ap) {
    // Custom error handling logic can be added here
    vfprintf(stderr, fmt, ap);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Initialize TIFF error handler
    TIFFSetErrorHandlerExt(CustomErrorHandler);

    // Convert fuzz input to a string
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        return 0;
    }

    // Buffer for error message
    char emsg[1024];

    // Check if the TIFF image can be converted to RGBA format
    if (TIFFRGBAImageOK(tif, emsg)) {
        // Allocate buffer for raw tile data
        uint32 tile = 0; // Assuming tile index 0 for simplicity
        tmsize_t tileSize = TIFFTileSize(tif);
        if (tileSize == 0) {
            TIFFClose(tif);
            return 0;
        }
        uint8_t* tileBuffer = (uint8_t*)malloc(tileSize);
        if (!tileBuffer) {
            TIFFClose(tif);
            return 0;
        }

        // Read raw tile data
        tmsize_t readSize = TIFFReadRawTile(tif, tile, tileBuffer, tileSize);
        if (readSize != (tmsize_t)(-1)) {
            // Write raw tile data back to the TIFF file
            TIFFWriteRawTile(tif, tile, tileBuffer, readSize);
        }

        // Free the allocated buffer
        free(tileBuffer);
    }

    // Flush data to ensure consistency
    TIFFFlushData(tif);

    // Close the TIFF object
    TIFFClose(tif);

    return 0;
}
