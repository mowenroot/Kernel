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
TIFF* CreateTIFFInMemory(const std::string& fuzzInput) {
    // Create a TIFF object in memory
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated resources
void FreeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    uint64_t* longArray = nullptr;
    tmsize_t longArraySize = 0;
    void* rawTileData = nullptr;
    tmsize_t rawTileDataSize = 0;

    // Derive API inputs from fuzz input
    if (size >= sizeof(uint32_t)) {
        tile = *reinterpret_cast<const uint32_t*>(data);
    }
    if (size >= sizeof(uint64_t)) {
        longArraySize = size / sizeof(uint64_t);
        longArray = reinterpret_cast<uint64_t*>(malloc(longArraySize * sizeof(uint64_t)));
        if (longArray) {
            memcpy(longArray, data, longArraySize * sizeof(uint64_t));
        }
    }
    if (size >= sizeof(tmsize_t)) {
        rawTileDataSize = *reinterpret_cast<const tmsize_t*>(data + size - sizeof(tmsize_t));
        rawTileData = malloc(rawTileDataSize);
        if (rawTileData) {
            memcpy(rawTileData, data, rawTileDataSize);
        }
    }

    // Call TIFFSwabArrayOfLong8
    if (longArray && longArraySize > 0) {
        TIFFSwabArrayOfLong8(longArray, longArraySize);
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        // Handle error
    }

    // Call TIFFWriteRawTile
    if (rawTileData && rawTileDataSize > 0) {
        if (TIFFWriteRawTile(tif, tile, rawTileData, rawTileDataSize) == (tmsize_t)(-1)) {
            // Handle error
        }
    }

    // Call TIFFReadRawTile
    if (rawTileData && rawTileDataSize > 0) {
        if (TIFFReadRawTile(tif, tile, rawTileData, rawTileDataSize) == (tmsize_t)(-1)) {
            // Handle error
        }
    }

    // Call TIFFRawStripSize64
    uint64_t stripSize = TIFFRawStripSize64(tif, tile);
    if (stripSize == (uint64_t)(-1)) {
        // Handle error
    }

    // Free allocated resources
    free(longArray);
    free(rawTileData);
    FreeTIFF(tif);

    return 0;
}
