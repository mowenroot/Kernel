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
    uint32_t tile = 0;
    tmsize_t tileSize = 0;
    void* tileData = nullptr;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size > 0) {
        tile = static_cast<uint32_t>(data[0]); // Use the first byte as the tile index
        tileSize = static_cast<tmsize_t>(data[1]); // Use the second byte as the tile size
        if (size > 2) {
            tileData = const_cast<uint8_t*>(data + 2); // Use the rest of the data as tile data
        }
    }

    // Call TIFFCurrentTile to get the current tile index
    uint32_t currentTile = TIFFCurrentTile(tif);

    // Call TIFFWriteRawTile to write raw tile data
    if (tileData && tileSize > 0) {
        tmsize_t writeResult = TIFFWriteRawTile(tif, tile, tileData, tileSize);
        if (writeResult == static_cast<tmsize_t>(-1)) {
            // Handle error
            FreeTIFF(tif);
            return 0;
        }
    }

    // Call TIFFReadRawTile to read raw tile data
    if (tileData && tileSize > 0) {
        tmsize_t readResult = TIFFReadRawTile(tif, tile, tileData, tileSize);
        if (readResult == static_cast<tmsize_t>(-1)) {
            // Handle error
            FreeTIFF(tif);
            return 0;
        }
    }

    // Call TIFFFlushData to flush data to the file
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        // Handle error
        FreeTIFF(tif);
        return 0;
    }

    // Call TIFFUnlinkDirectory to unlink a directory
    uint16_t dirn = static_cast<uint16_t>(tile % 10); // Use a simple modulo operation to generate a directory number
    int unlinkResult = TIFFUnlinkDirectory(tif, dirn);
    if (unlinkResult == 0) {
        // Handle error
        FreeTIFF(tif);
        return 0;
    }

    // Free the TIFF object and associated resources
    FreeTIFF(tif);

    return 0;
}
