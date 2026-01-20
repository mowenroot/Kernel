#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createInMemoryTIFF(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("mem", &s); // Pass the address of the istringstream
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
    void* buffer = nullptr;
    tmsize_t bufferSize = 0;

    // Initialize the TIFF object from fuzz input
    tif = createInMemoryTIFF(data, size);
    if (!tif) {
        return 0;
    }

    // Check if the TIFF image can be converted to RGBA format
    if (TIFFRGBAImageOK(tif, emsg)) {
        // Read an encoded tile from the TIFF image
        bufferSize = TIFFTileSize(tif);
        buffer = malloc(bufferSize);
        if (!buffer) {
            freeTIFF(tif);
            return 0;
        }

        if (TIFFReadEncodedTile(tif, tile, buffer, bufferSize) != (tmsize_t)(-1)) {
            // Write the encoded tile back to the TIFF image
            if (TIFFWriteEncodedTile(tif, tile, buffer, bufferSize) != (tmsize_t)(-1)) {
                // Flush the TIFF image to ensure all changes are written
                TIFFFlush(tif);
            }
        }

        // Free the buffer
        free(buffer);
    }

    // Free the TIFF object
    freeTIFF(tif);

    return 0;
}
