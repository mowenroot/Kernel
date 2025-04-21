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
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    std::string input = FuzzInputToString(data, size);
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
}

// Function to free the TIFF object
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    tmsize_t tileSize = 0;
    tmsize_t rawStripSize = 0;
    tmsize_t readSize = 0;
    uint32* longArray = nullptr;
    uint16* shortArray = nullptr;
    uint32 tileIndex = 0;
    void* buffer = nullptr;

    // Initialize the TIFF object in memory
    tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Calculate the size of a TIFF tile
    tileSize = TIFFTileSize(tif);
    if (tileSize <= 0) {
        freeTIFF(tif);
        return 0;
    }

    // Calculate the size of a TIFF strip
    rawStripSize = TIFFRawStripSize(tif, tileIndex);
    if (rawStripSize <= 0) {
        freeTIFF(tif);
        return 0;
    }

    // Allocate memory for the buffer to read the raw tile data
    buffer = malloc(tileSize);
    if (!buffer) {
        freeTIFF(tif);
        return 0;
    }

    // Read the raw tile data
    readSize = TIFFReadRawTile(tif, tileIndex, buffer, tileSize);
    if (readSize <= 0) {
        free(buffer);
        freeTIFF(tif);
        return 0;
    }

    // Allocate memory for the long array and initialize it with the buffer data
    longArray = (uint32*)malloc(tileSize);
    if (!longArray) {
        free(buffer);
        freeTIFF(tif);
        return 0;
    }
    memcpy(longArray, buffer, tileSize);

    // Swap the byte order of the long array
    TIFFSwabArrayOfLong(longArray, tileSize / sizeof(uint32));

    // Allocate memory for the short array and initialize it with the buffer data
    shortArray = (uint16*)malloc(tileSize);
    if (!shortArray) {
        free(longArray);
        free(buffer);
        freeTIFF(tif);
        return 0;
    }
    memcpy(shortArray, buffer, tileSize);

    // Swap the byte order of the short array
    TIFFSwabArrayOfShort(shortArray, tileSize / sizeof(uint16));

    // Free all allocated resources
    free(shortArray);
    free(longArray);
    free(buffer);
    freeTIFF(tif);

    return 0;
}
