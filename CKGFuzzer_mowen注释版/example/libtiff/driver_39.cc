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

// Function to create a TIFF object in memory from the fuzz input
TIFF* createTIFFInMemory(const std::string& input) {
    // Create a TIFF object in memory
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated resources
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(input);
    if (!tif) {
        return 0;
    }

    // Buffer for raw tile data
    uint8_t* rawTileData = nullptr;
    tmsize_t rawTileSize = 0;

    // Buffer for error message
    char emsg[1024];

    // Initialize variables for API calls
    uint32 tile = 0;
    uint32 nrows = 0;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size >= sizeof(uint32)) {
        tile = *reinterpret_cast<const uint32*>(data);
        nrows = *reinterpret_cast<const uint32*>(data + sizeof(uint32));
    }

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA format
    int rgbaOk = TIFFRGBAImageOK(tif, emsg);
    if (rgbaOk) {
        // Calculate the size of a strip in bytes
        uint64 stripSize = TIFFVStripSize64(tif, nrows);
        if (stripSize > 0) {
            // Allocate memory for raw tile data
            rawTileData = static_cast<uint8_t*>(malloc(stripSize));
            if (rawTileData) {
                rawTileSize = static_cast<tmsize_t>(stripSize);

                // Read raw tile data
                tmsize_t readSize = TIFFReadRawTile(tif, tile, rawTileData, rawTileSize);
                if (readSize > 0) {
                    // Write raw tile data
                    tmsize_t writeSize = TIFFWriteRawTile(tif, tile, rawTileData, readSize);
                    if (writeSize != readSize) {
                        // Handle write error
                    }
                } else {
                    // Handle read error
                }

                // Free allocated memory
                free(rawTileData);
            }
        }
    }

    // Flush data to ensure consistency
    int flushStatus = TIFFFlushData(tif);
    if (flushStatus != 1) {
        // Handle flush error
    }

    // Free the TIFF object and associated resources
    freeTIFF(tif);

    return 0;
}
