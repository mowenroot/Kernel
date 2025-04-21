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

// Function to free the TIFF object and associated memory
void FreeTIFFInMemory(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    uint32 tileWidth = 0, tileHeight = 0;
    tmsize_t tileSize = 0;
    uint32 stripSize = 0;
    void* buffer = nullptr;

    // Initialize TIFF object in memory
    tif = CreateTIFFInMemory(data, size);
    if (!tif) {
        return 0; // Early exit if TIFF object creation fails
    }

    // Calculate tile size
    tileSize = TIFFTileSize(tif);
    if (tileSize <= 0) {
        FreeTIFFInMemory(tif);
        return 0; // Early exit if tile size calculation fails
    }

    // Set default tile size
    TIFFDefaultTileSize(tif, &tileWidth, &tileHeight);

    // Calculate default strip size
    stripSize = TIFFDefaultStripSize(tif, tileWidth);

    // Allocate buffer for reading/writing tiles
    buffer = malloc(tileSize);
    if (!buffer) {
        FreeTIFFInMemory(tif);
        return 0; // Early exit if buffer allocation fails
    }

    // Write raw tile data
    uint32 tileIndex = 0; // Assuming tile index 0 for simplicity
    tmsize_t writeSize = TIFFWriteRawTile(tif, tileIndex, buffer, tileSize);
    if (writeSize != tileSize) {
        free(buffer);
        FreeTIFFInMemory(tif);
        return 0; // Early exit if write operation fails
    }

    // Read raw tile data
    tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, buffer, tileSize);
    if (readSize != tileSize) {
        free(buffer);
        FreeTIFFInMemory(tif);
        return 0; // Early exit if read operation fails
    }

    // Free allocated resources
    free(buffer);
    FreeTIFFInMemory(tif);

    return 0; // Return 0 to indicate successful execution
}
