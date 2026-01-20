#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function prototype for the fuzz driver
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

// Helper function to create a TIFF object from fuzz input
TIFF* createTIFFFromInput(const uint8_t *data, size_t size) {
    // Create a std::istringstream from the fuzz input data
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));
    // Create a TIFF object in memory using the string stream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    uint32 tileIndex = 0;
    uint32 tagValue = 0;
    uint16 tagID = 0;
    uint64 offset = 0;
    uint8_t* buffer = nullptr;
    tmsize_t bufferSize = 0;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32) * 3) {
        return 0;
    }

    // Create a TIFF object from the fuzz input
    tif = createTIFFFromInput(data, size);
    if (!tif) {
        return 0;
    }

    // Extract necessary values from the fuzz input
    memcpy(&tileIndex, data, sizeof(uint32));
    memcpy(&tagValue, data + sizeof(uint32), sizeof(uint32));
    memcpy(&tagID, data + 2 * sizeof(uint32), sizeof(uint16));
    memcpy(&offset, data + 2 * sizeof(uint32) + sizeof(uint16), sizeof(uint64));

    // Ensure bounds for tileIndex and tagID
    tileIndex %= 1000; // Arbitrary limit to prevent excessive values
    tagID %= 65536;    // TIFF tags are 16-bit

    // Call TIFFReadDirectory
    if (TIFFReadDirectory(tif) == 0) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    bufferSize = TIFFTileSize(tif);
    buffer = (uint8_t*)malloc(bufferSize);
    if (buffer) {
        TIFFReadRawTile(tif, tileIndex, buffer, bufferSize);
        free(buffer);
    }

    // Call TIFFFieldWithTag
    const TIFFField* field = TIFFFieldWithTag(tif, tagID);
    if (!field) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadBufferSetup
    if (!TIFFReadBufferSetup(tif, nullptr, bufferSize)) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFSetField
    if (!TIFFSetField(tif, tagID, tagValue)) {
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    TIFFClose(tif);
    return 0;
}
