#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object from fuzz input data
TIFF* createTIFFFromFuzzInput(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated resources
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    uint64_t* tileData = nullptr;
    uint32_t tileIndex = 0;
    uint32_t tag = 0;
    const TIFFField* field = nullptr;
    int readDirResult = 0;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Create a TIFF object from the fuzz input
    tif = createTIFFFromFuzzInput(data, size);
    if (!tif) {
        return 0;
    }

    // Extract a tile index from the fuzz input
    tileIndex = *reinterpret_cast<const uint32_t*>(data);

    // Allocate memory for tile data
    tileData = static_cast<uint64_t*>(_TIFFmalloc(sizeof(uint64_t)));
    if (!tileData) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFSwabLong8 to reverse the byte order of a 64-bit integer
    TIFFSwabLong8(tileData);

    // Call TIFFReadEncodedTile to read and decode a tile
    if (TIFFReadEncodedTile(tif, tileIndex, tileData, sizeof(uint64_t)) == -1) {
        // Handle error
    }

    // Call TIFFReadRawTile to read raw tile data
    if (TIFFReadRawTile(tif, tileIndex, tileData, sizeof(uint64_t)) == -1) {
        // Handle error
    }

    // Extract a tag from the fuzz input
    tag = *reinterpret_cast<const uint32_t*>(data + sizeof(uint32_t));

    // Call TIFFFieldWithTag to retrieve a TIFF field structure
    field = TIFFFieldWithTag(tif, tag);
    if (!field) {
        // Handle error
    }

    // Call TIFFReadDirectory to read and process TIFF directory entries
    readDirResult = TIFFReadDirectory(tif);
    if (!readDirResult) {
        // Handle error
    }

    // Free allocated memory
    _TIFFfree(tileData);
    freeTIFF(tif);

    return 0;
}
