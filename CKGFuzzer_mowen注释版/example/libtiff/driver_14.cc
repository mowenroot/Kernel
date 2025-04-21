#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to handle TIFF warnings
static void TIFFWarningHandler(thandle_t, const char* module, const char* fmt, va_list ap) {
    // Custom warning handler logic can be added here
    vfprintf(stderr, fmt, ap);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Wrap the input data in a std::istringstream object
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("mem", &s);
    if (!tif) {
        return 0;
    }

    // Set a custom warning handler
    TIFFSetWarningHandlerExt(TIFFWarningHandler);

    // Allocate buffers for reading and writing tiles
    tmsize_t tileSize = TIFFTileSize(tif);
    if (tileSize == 0) {
        TIFFClose(tif);
        return 0;
    }

    uint8_t* readBuffer = (uint8_t*)malloc(tileSize);
    uint8_t* writeBuffer = (uint8_t*)malloc(tileSize);
    if (!readBuffer || !writeBuffer) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Initialize write buffer with some data
    memcpy(writeBuffer, data, size > tileSize ? tileSize : size);

    // Perform operations on the TIFF file
    uint32 tile = 0;
    tmsize_t readBytes = TIFFReadEncodedTile(tif, tile, readBuffer, tileSize);
    if (readBytes != (tmsize_t)(-1)) {
        // Write the read data back to the TIFF file
        tmsize_t writeBytes = TIFFWriteEncodedTile(tif, tile, writeBuffer, tileSize);
        if (writeBytes == (tmsize_t)(-1)) {
            free(readBuffer);
            free(writeBuffer);
            TIFFClose(tif);
            return 0;
        }
    }

    // Checkpoint the directory
    if (TIFFCheckpointDirectory(tif) != 1) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Rewrite the directory
    if (TIFFRewriteDirectory(tif) != 1) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    free(readBuffer);
    free(writeBuffer);
    TIFFClose(tif);

    return 0;
}
