#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include sstream for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from a string
TIFF* CreateTIFFInMemory(const std::string& data) {
    // Create a TIFF object in memory
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    void* buffer = nullptr;
    tmsize_t bufferSize = 0;

    // Ensure proper bounds checking
    if (size >= sizeof(uint32_t)) {
        tile = *reinterpret_cast<const uint32_t*>(data);
    }

    // Allocate buffer for reading/writing tiles
    bufferSize = TIFFTileSize(tif);
    if (bufferSize > 0) {
        buffer = malloc(bufferSize);
        if (!buffer) {
            TIFFClose(tif);
            return 0;
        }
    }

    // Call TIFFCheckTile to validate tile coordinates
    if (TIFFCheckTile(tif, tile, tile, 0, 0) != 1) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteEncodedTile to write encoded tile data
    if (TIFFWriteEncodedTile(tif, tile, buffer, bufferSize) == (tmsize_t)(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadEncodedTile to read encoded tile data
    if (TIFFReadEncodedTile(tif, tile, buffer, bufferSize) == (tmsize_t)(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFFlushData to flush buffered data
    if (TIFFFlushData(tif) != 1) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFRewriteDirectory to rewrite the TIFF directory
    if (TIFFRewriteDirectory(tif) != 1) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated resources
    free(buffer);
    TIFFClose(tif);

    return 0;
}
