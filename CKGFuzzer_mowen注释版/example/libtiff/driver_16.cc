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
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
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
    uint64_t* longArray = nullptr;
    tmsize_t longArraySize = 0;
    uint32_t tileIndex = 0;
    void* tileData = nullptr;
    tmsize_t tileDataSize = 0;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size >= sizeof(uint64_t)) {
        longArraySize = size / sizeof(uint64_t);
        longArray = static_cast<uint64_t*>(malloc(longArraySize * sizeof(uint64_t)));
        if (longArray) {
            memcpy(longArray, data, longArraySize * sizeof(uint64_t));
        }
    }

    if (size >= sizeof(uint32_t)) {
        tileIndex = *reinterpret_cast<const uint32_t*>(data);
    }

    if (size >= sizeof(tmsize_t)) {
        tileDataSize = *reinterpret_cast<const tmsize_t*>(data);
        tileData = malloc(tileDataSize);
        if (tileData) {
            memcpy(tileData, data, tileDataSize);
        }
    }

    // Call TIFFSwabArrayOfLong8
    if (longArray && longArraySize > 0) {
        TIFFSwabArrayOfLong8(longArray, longArraySize);
    }

    // Call TIFFSetupStrips
    if (!TIFFSetupStrips(tif)) {
        // Handle error
        FreeTIFF(tif);
        free(longArray);
        free(tileData);
        return 0;
    }

    // Call TIFFWriteRawTile
    if (tileData && tileDataSize > 0) {
        if (TIFFWriteRawTile(tif, tileIndex, tileData, tileDataSize) == static_cast<tmsize_t>(-1)) {
            // Handle error
            FreeTIFF(tif);
            free(longArray);
            free(tileData);
            return 0;
        }
    }

    // Call TIFFReadRawTile
    if (tileData && tileDataSize > 0) {
        if (TIFFReadRawTile(tif, tileIndex, tileData, tileDataSize) == static_cast<tmsize_t>(-1)) {
            // Handle error
            FreeTIFF(tif);
            free(longArray);
            free(tileData);
            return 0;
        }
    }

    // Call TIFFFlushData
    if (!TIFFFlushData(tif)) {
        // Handle error
        FreeTIFF(tif);
        free(longArray);
        free(tileData);
        return 0;
    }

    // Free allocated resources
    FreeTIFF(tif);
    free(longArray);
    free(tileData);

    return 0;
}
