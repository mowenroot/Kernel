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
        return 0;
    }

    // Initialize variables
    uint64_t* longArray = nullptr;
    tmsize_t longArraySize = 0;
    uint32_t tileIndex = 0;
    void* tileData = nullptr;
    tmsize_t tileDataSize = 0;
    uint16_t directoryIndex = 0;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size >= sizeof(uint64_t) + sizeof(uint32_t) + sizeof(tmsize_t) + sizeof(uint16_t)) {
        // Derive API inputs from fuzz input
        longArraySize = size / sizeof(uint64_t);
        longArray = static_cast<uint64_t*>(malloc(longArraySize * sizeof(uint64_t)));
        if (longArray) {
            memcpy(longArray, data, longArraySize * sizeof(uint64_t));
            TIFFSwabArrayOfLong8(longArray, longArraySize);
        }

        tileIndex = *reinterpret_cast<const uint32_t*>(data + longArraySize * sizeof(uint64_t));
        tileDataSize = *reinterpret_cast<const tmsize_t*>(data + longArraySize * sizeof(uint64_t) + sizeof(uint32_t));
        tileData = malloc(tileDataSize);
        if (tileData) {
            memcpy(tileData, data + longArraySize * sizeof(uint64_t) + sizeof(uint32_t) + sizeof(tmsize_t), tileDataSize);
        }

        directoryIndex = *reinterpret_cast<const uint16_t*>(data + longArraySize * sizeof(uint64_t) + sizeof(uint32_t) + sizeof(tmsize_t) + tileDataSize);
    }

    // Call TIFFSetDirectory
    if (TIFFSetDirectory(tif, directoryIndex) != 1) {
        // Handle error
    }

    // Call TIFFWriteRawTile
    if (tileData) {
        if (TIFFWriteRawTile(tif, tileIndex, tileData, tileDataSize) == static_cast<tmsize_t>(-1)) {
            // Handle error
        }
    }

    // Call TIFFReadRawTile
    if (tileData) {
        if (TIFFReadRawTile(tif, tileIndex, tileData, tileDataSize) == static_cast<tmsize_t>(-1)) {
            // Handle error
        }
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        // Handle error
    }

    // Free allocated resources
    free(longArray);
    free(tileData);
    FreeTIFF(tif);

    return 0;
}
