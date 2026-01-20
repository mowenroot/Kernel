#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object in memory from the fuzz input data
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object created in memory
void freeTIFFInMemory(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input data
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize variables for API calls
    uint64_t tileIndex = 0;
    uint64_t* tileData = nullptr;
    tmsize_t tileSize = 0;
    int isTiledResult = 0;
    int rewriteResult = 0;
    const unsigned char* bitRevTable = nullptr;

    // Extract tile index from the fuzz input data
    memcpy(&tileIndex, data, sizeof(uint64_t));

    // Allocate memory for tile data
    tileSize = size - sizeof(uint64_t);
    tileData = (uint64_t*)malloc(tileSize);
    if (!tileData) {
        freeTIFFInMemory(tif);
        return 0;
    }

    // Call TIFFIsTiled to check if the TIFF image is tiled
    isTiledResult = TIFFIsTiled(tif);

    // Call TIFFReadRawTile to read raw tile data
    tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, tileData, tileSize);
    if (readSize == (tmsize_t)(-1)) {
        // Handle error
        free(tileData);
        freeTIFFInMemory(tif);
        return 0;
    }

    // Call TIFFSwabArrayOfLong8 to reverse the byte order of the tile data
    TIFFSwabArrayOfLong8(tileData, readSize / sizeof(uint64_t));

    // Call TIFFRewriteDirectory to rewrite the TIFF directory
    rewriteResult = TIFFRewriteDirectory(tif);
    if (rewriteResult == 0) {
        // Handle error
        free(tileData);
        freeTIFFInMemory(tif);
        return 0;
    }

    // Call TIFFGetBitRevTable to get the bit reversal table
    bitRevTable = TIFFGetBitRevTable(1);

    // Free allocated resources
    free(tileData);
    freeTIFFInMemory(tif);

    return 0;
}
