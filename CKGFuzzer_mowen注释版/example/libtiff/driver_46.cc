#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFFStream object
TIFF* CreateInMemoryTIFF(const uint8_t* data, size_t size) {
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

// Function to free the TIFF object
void FreeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    uint64_t* longArray = nullptr;
    uint16_t dirn = 0;
    uint32_t tile = 0;
    void* rawTileBuffer = nullptr;
    tmsize_t rawTileBufferSize = 0;

    // Initialize the TIFF object from fuzz input
    tif = CreateInMemoryTIFF(data, size);
    if (!tif) {
        return 0; // Early exit if TIFF creation fails
    }

    // Ensure proper bounds checking for array sizes
    if (size >= sizeof(uint64_t)) {
        longArray = (uint64_t*)malloc(size);
        if (longArray) {
            memcpy(longArray, data, size);
            TIFFSwabArrayOfLong8(longArray, size / sizeof(uint64_t));
            free(longArray);
        }
    }

    // Extract directory number from fuzz input
    if (size >= sizeof(uint16_t)) {
        dirn = *((uint16_t*)data);
        TIFFUnlinkDirectory(tif, dirn);
    }

    // Rewrite the directory
    TIFFRewriteDirectory(tif);

    // Extract tile number from fuzz input
    if (size >= sizeof(uint32_t)) {
        tile = *((uint32_t*)(data + sizeof(uint16_t)));
        rawTileBufferSize = TIFFTileSize(tif);
        if (rawTileBufferSize > 0) {
            rawTileBuffer = malloc(rawTileBufferSize);
            if (rawTileBuffer) {
                TIFFReadRawTile(tif, tile, rawTileBuffer, rawTileBufferSize);
                free(rawTileBuffer);
            }
        }
    }

    // Retrieve and log the current directory offset
    uint64_t currentDirOffset = TIFFCurrentDirOffset(tif);
    (void)currentDirOffset; // Suppress unused variable warning

    // Free allocated resources
    FreeTIFF(tif);

    return 0; // Non-zero return values are reserved for future use
}
