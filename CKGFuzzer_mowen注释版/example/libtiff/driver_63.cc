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

// Function to create a TIFF object in memory from a string
TIFF* CreateTIFFInMemory(const std::string& data) {
    // Create a TIFF object in memory
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
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
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32 tile = 0;
    uint32 row = 0;
    tmsize_t tileSize = 0;
    uint64* longArray = nullptr;
    tmsize_t longArraySize = 0;
    void* rawTileData = nullptr;

    // Ensure proper bounds checking
    if (size >= sizeof(uint32) * 3) {
        tile = *reinterpret_cast<const uint32*>(data);
        row = *reinterpret_cast<const uint32*>(data + sizeof(uint32));
        tileSize = *reinterpret_cast<const tmsize_t*>(data + 2 * sizeof(uint32));
    }

    // Allocate memory for long array
    longArraySize = tileSize / sizeof(uint64);
    if (longArraySize > 0) {
        longArray = static_cast<uint64*>(malloc(longArraySize * sizeof(uint64)));
        if (!longArray) {
            FreeTIFF(tif);
            return 0; // Memory allocation failed
        }
        memset(longArray, 0, longArraySize * sizeof(uint64));
    }

    // Allocate memory for raw tile data
    if (tileSize > 0) {
        rawTileData = malloc(tileSize);
        if (!rawTileData) {
            free(longArray);
            FreeTIFF(tif);
            return 0; // Memory allocation failed
        }
        memset(rawTileData, 0, tileSize);
    }

    // Call TIFFSwabArrayOfLong8
    if (longArray) {
        TIFFSwabArrayOfLong8(longArray, longArraySize);
    }

    // Call TIFFWriteRawTile
    if (rawTileData) {
        tmsize_t writtenSize = TIFFWriteRawTile(tif, tile, rawTileData, tileSize);
        if (writtenSize != tileSize) {
            // Handle error
        }
    }

    // Call TIFFReadRawTile
    if (rawTileData) {
        tmsize_t readSize = TIFFReadRawTile(tif, tile, rawTileData, tileSize);
        if (readSize != tileSize) {
            // Handle error
        }
    }

    // Call TIFFRewriteDirectory
    int rewriteResult = TIFFRewriteDirectory(tif);
    if (rewriteResult != 1) {
        // Handle error
    }

    // Call TIFFCurrentRow
    row = TIFFCurrentRow(tif);

    // Free allocated memory
    free(longArray);
    free(rawTileData);

    // Free TIFF object
    FreeTIFF(tif);

    return 0; // Return 0 to indicate success
}
