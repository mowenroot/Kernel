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
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    std::string inputStr = fuzzInputToString(data, size);
    std::istringstream s(inputStr); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        // Not enough data to proceed
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Extract necessary data from the fuzz input
    uint64_t* longArray = reinterpret_cast<uint64_t*>(const_cast<uint8_t*>(data));
    tmsize_t arraySize = size / sizeof(uint64_t);
    uint32_t tile = static_cast<uint32_t>(data[0]);
    uint32_t nrows = static_cast<uint32_t>(data[1]);
    tmsize_t bufferSize = size - 8; // Subtract 8 bytes for tile and nrows
    void* buffer = malloc(bufferSize);
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }
    memcpy(buffer, data + 8, bufferSize);

    // Perform operations using the provided APIs
    TIFFSwabArrayOfLong8(longArray, arraySize);

    if (TIFFFlushData(tif) != 1) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buffer, bufferSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, buffer, readSize);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    uint64_t tileSize = TIFFVTileSize64(tif, nrows);
    if (tileSize == 0) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    free(buffer);
    TIFFClose(tif);

    return 0;
}
