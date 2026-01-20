#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = TIFFTileSize(tif);
    void* buf = malloc(tileSize);
    if (!buf) {
        freeTIFF(tif);
        return 0; // Failed to allocate buffer
    }

    // Initialize YCbCr to RGB conversion
    TIFFYCbCrToRGB ycbcr;
    float luma[3] = {0.299F, 0.587F, 0.114F};
    float refBlackWhite[6] = {0.0F, 255.0F, 128.0F, 255.0F, 128.0F, 255.0F};
    int ycbcrInitResult = TIFFYCbCrToRGBInit(&ycbcr, luma, refBlackWhite);
    if (ycbcrInitResult != 0) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to initialize YCbCr to RGB conversion
    }

    // Read encoded tile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buf, tileSize);
    if (readSize == (tmsize_t)(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to read encoded tile
    }

    // Swap byte order of the read data
    TIFFSwabArrayOfShort((uint16*)buf, readSize / sizeof(uint16));

    // Rewrite directory
    int rewriteResult = TIFFRewriteDirectory(tif);
    if (rewriteResult != 1) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to rewrite directory
    }

    // Flush data
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to flush data
    }

    // Free allocated resources
    free(buf);
    freeTIFF(tif);

    return 0; // Success
}
