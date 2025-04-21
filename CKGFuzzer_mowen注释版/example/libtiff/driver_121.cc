#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include sstream for std::istringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzData = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzData);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    tmsize_t tileSize = 1024; // Arbitrary size for the tile buffer
    void* tileBuffer = malloc(tileSize);
    if (!tileBuffer) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadBufferSetup to initialize the read buffer
    if (TIFFReadBufferSetup(tif, tileBuffer, tileSize) != 1) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile to read raw tile data
    tmsize_t readSize = TIFFReadRawTile(tif, tile, tileBuffer, tileSize);
    if (readSize == (tmsize_t)(-1)) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteRawTile to write raw tile data
    tmsize_t writeSize = TIFFWriteRawTile(tif, tile, tileBuffer, readSize);
    if (writeSize == (tmsize_t)(-1)) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFFlushData to flush data to the file
    if (TIFFFlushData(tif) != 1) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFUnlinkDirectory to unlink a directory
    uint16_t dirn = 1; // Arbitrary directory number
    if (TIFFUnlinkDirectory(tif, dirn) != 1) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated resources
    free(tileBuffer);
    TIFFClose(tif);

    return 0;
}
