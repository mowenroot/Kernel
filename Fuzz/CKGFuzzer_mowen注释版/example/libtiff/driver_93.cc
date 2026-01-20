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
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        // Not enough data to proceed
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = CreateTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Extract necessary data from the fuzz input
    uint64_t* longArray = reinterpret_cast<uint64_t*>(malloc(size));
    if (!longArray) {
        TIFFClose(tif);
        return 0;
    }
    memcpy(longArray, data, size);

    // Call TIFFSwabArrayOfLong8
    TIFFSwabArrayOfLong8(longArray, size / sizeof(uint64_t));

    // Call TIFFGetMode
    int mode = TIFFGetMode(tif);
    if (mode == -1) {
        free(longArray);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadEncodedTile
    uint32_t tile = 0; // Assuming tile 0 for simplicity
    void* tileBuffer = malloc(size);
    if (!tileBuffer) {
        free(longArray);
        TIFFClose(tif);
        return 0;
    }
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, tileBuffer, size);
    if (readSize == (tmsize_t)(-1)) {
        free(longArray);
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReverseBits
    TIFFReverseBits(reinterpret_cast<uint8_t*>(tileBuffer), readSize);

    // Call TIFFGetBitRevTable
    const unsigned char* bitRevTable = TIFFGetBitRevTable(1);
    if (!bitRevTable) {
        free(longArray);
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    free(longArray);
    free(tileBuffer);
    TIFFClose(tif);

    return 0;
}
