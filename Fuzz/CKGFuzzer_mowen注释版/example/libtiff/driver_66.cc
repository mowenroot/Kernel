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
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
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

    // Initialize variables for API calls
    TIFFCIELabToRGB cielab;
    TIFFDisplay display;
    float refWhite[3] = {1.0f, 1.0f, 1.0f}; // Example reference white point

    // Initialize the TIFFCIELabToRGB structure
    int initResult = TIFFCIELabToRGBInit(&cielab, &display, refWhite);
    if (initResult != 0) {
        FreeTIFF(tif);
        return 0; // Failed to initialize TIFFCIELabToRGB
    }

    // Set a TIFF field (example: setting the image width)
    uint32 width = 1024; // Example width
    int setFieldResult = TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width);
    if (setFieldResult != 1) {
        FreeTIFF(tif);
        return 0; // Failed to set TIFF field
    }

    // Write raw tile data (example: writing a single tile)
    uint32 tileIndex = 0; // Example tile index
    tmsize_t tileSize = 1024; // Example tile size
    void* tileData = malloc(tileSize);
    if (!tileData) {
        FreeTIFF(tif);
        return 0; // Failed to allocate memory for tile data
    }
    memset(tileData, 0, tileSize); // Initialize tile data

    tmsize_t writeResult = TIFFWriteRawTile(tif, tileIndex, tileData, tileSize);
    free(tileData);
    if (writeResult != tileSize) {
        FreeTIFF(tif);
        return 0; // Failed to write raw tile
    }

    // Read raw tile data (example: reading the same tile)
    void* readBuffer = malloc(tileSize);
    if (!readBuffer) {
        FreeTIFF(tif);
        return 0; // Failed to allocate memory for read buffer
    }
    memset(readBuffer, 0, tileSize); // Initialize read buffer

    tmsize_t readResult = TIFFReadRawTile(tif, tileIndex, readBuffer, tileSize);
    free(readBuffer);
    if (readResult != tileSize) {
        FreeTIFF(tif);
        return 0; // Failed to read raw tile
    }

    // Flush data to ensure consistency
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        FreeTIFF(tif);
        return 0; // Failed to flush data
    }

    // Free the TIFF object and associated resources
    FreeTIFF(tif);

    return 0; // Success
}
