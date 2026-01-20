#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from the fuzz input
TIFF* CreateTIFFInMemory(const uint8_t* data, size_t size) {
    std::string input = FuzzInputToString(data, size);
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        // Need at least 8 bytes for meaningful operations
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = CreateTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Extract necessary data from the fuzz input
    uint64_t* longArray = reinterpret_cast<uint64_t*>(const_cast<uint8_t*>(data));
    tmsize_t arraySize = size / sizeof(uint64_t);
    uint32_t tileIndex = static_cast<uint32_t>(data[0]);
    tmsize_t rawTileSize = static_cast<tmsize_t>(data[1]) * 1024; // Assume tile size in KB

    // Allocate buffer for raw tile data
    void* rawTileBuffer = malloc(rawTileSize);
    if (!rawTileBuffer) {
        TIFFClose(tif);
        return 0;
    }

    // Perform operations using the provided APIs
    TIFFSwabArrayOfLong8(longArray, arraySize);

    if (TIFFIsByteSwapped(tif)) {
        // Handle byte-swapped TIFF
    }

    if (TIFFWriteRawTile(tif, tileIndex, rawTileBuffer, rawTileSize) == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    if (TIFFReadRawTile(tif, tileIndex, rawTileBuffer, rawTileSize) == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    if (TIFFFlushData(tif) != 1) {
        // Handle error
    }

    // Free allocated resources
    free(rawTileBuffer);
    TIFFClose(tif);

    return 0;
}
