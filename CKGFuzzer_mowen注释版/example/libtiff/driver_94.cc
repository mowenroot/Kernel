#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const std::string& input) {
    TIFF* tif = TIFFStreamOpen("MemTIFF", new std::istringstream(input));
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(input);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    TIFFReadWriteProc readProc = nullptr;
    TIFFExtendProc extender = nullptr;
    void* clientInfo = nullptr;
    int customDirResult = 0;
    tmsize_t rawTileResult = 0;

    // Get the read procedure
    readProc = TIFFGetReadProc(tif);
    if (!readProc) {
        TIFFClose(tif);
        return 0;
    }

    // Set the tag extender
    extender = TIFFSetTagExtender([](TIFF*){});
    if (!extender) {
        TIFFClose(tif);
        return 0;
    }

    // Set client info
    clientInfo = malloc(sizeof(uint32_t));
    if (!clientInfo) {
        TIFFClose(tif);
        return 0;
    }
    TIFFSetClientInfo(tif, clientInfo, "FuzzClientInfo");

    // Read custom directory
    customDirResult = TIFFReadCustomDirectory(tif, 0, nullptr);
    if (customDirResult != 1) {
        free(clientInfo);
        TIFFClose(tif);
        return 0;
    }

    // Read raw tile
    uint32_t tileIndex = 0;
    void* buffer = malloc(1024); // Allocate a buffer for the tile data
    if (!buffer) {
        free(clientInfo);
        TIFFClose(tif);
        return 0;
    }
    rawTileResult = TIFFReadRawTile(tif, tileIndex, buffer, 1024);
    if (rawTileResult == (tmsize_t)(-1)) {
        free(buffer);
        free(clientInfo);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    free(buffer);
    free(clientInfo);
    TIFFClose(tif);

    return 0;
}
