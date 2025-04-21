#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::stringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const std::string& input) {
    return TIFFStreamOpen("MemTIFF", new std::istringstream(input)); // Changed std::stringstream to std::istringstream
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(input);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Allocate buffers for tile data
    uint64_t* tileData = static_cast<uint64_t*>(malloc(size));
    if (!tileData) {
        TIFFClose(tif);
        return 0; // Failed to allocate memory
    }

    // Initialize tile data with fuzz input
    memcpy(tileData, data, size);

    // Perform TIFFSwabArrayOfLong8
    TIFFSwabArrayOfLong8(tileData, size / sizeof(uint64_t));

    // Perform TIFFReadEncodedTile
    uint32_t tile = 0; // Assuming tile index 0 for simplicity
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, tileData, size);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(tileData);
        TIFFClose(tif);
        return 0; // Failed to read tile
    }

    // Perform TIFFWriteEncodedTile
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, tileData, readSize);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        free(tileData);
        TIFFClose(tif);
        return 0; // Failed to write tile
    }

    // Perform TIFFUnlinkDirectory
    uint16_t dirn = 0; // Assuming directory index 0 for simplicity
    if (!TIFFUnlinkDirectory(tif, dirn)) {
        free(tileData);
        TIFFClose(tif);
        return 0; // Failed to unlink directory
    }

    // Perform TIFFFlush
    if (!TIFFFlush(tif)) {
        free(tileData);
        TIFFClose(tif);
        return 0; // Failed to flush data
    }

    // Free allocated resources
    free(tileData);
    TIFFClose(tif);

    return 0; // Success
}
