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
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
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
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint64_t tileIndex = 0;
    uint64_t* tileData = nullptr;
    tmsize_t tileSize = 0;

    // Ensure the fuzz input size is sufficient for our operations
    if (size < sizeof(uint64_t) * 2) {
        FreeTIFF(tif);
        return 0; // Insufficient data
    }

    // Extract tile index and tile size from fuzz input
    memcpy(&tileIndex, data, sizeof(uint64_t));
    memcpy(&tileSize, data + sizeof(uint64_t), sizeof(tmsize_t));

    // Allocate memory for tile data
    tileData = static_cast<uint64_t*>(malloc(tileSize));
    if (!tileData) {
        FreeTIFF(tif);
        return 0; // Memory allocation failed
    }

    // Initialize tile data with a safe value
    memset(tileData, 0, tileSize);

    // Call TIFFSwabArrayOfLong8 to reverse byte order
    TIFFSwabArrayOfLong8(tileData, tileSize / sizeof(uint64_t));

    // Call TIFFWriteRawTile to write raw tile data
    tmsize_t writtenSize = TIFFWriteRawTile(tif, static_cast<uint32>(tileIndex), tileData, tileSize);
    if (writtenSize == static_cast<tmsize_t>(-1)) {
        free(tileData);
        FreeTIFF(tif);
        return 0; // Write operation failed
    }

    // Call TIFFFlushData to ensure data integrity
    if (TIFFFlushData(tif) != 1) {
        free(tileData);
        FreeTIFF(tif);
        return 0; // Flush operation failed
    }

    // Call TIFFReadRawTile to read raw tile data
    tmsize_t readSize = TIFFReadRawTile(tif, static_cast<uint32>(tileIndex), tileData, tileSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(tileData);
        FreeTIFF(tif);
        return 0; // Read operation failed
    }

    // Free allocated resources
    free(tileData);
    FreeTIFF(tif);

    return 0; // Success
}
