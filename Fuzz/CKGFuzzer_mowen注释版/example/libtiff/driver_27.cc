#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object in memory from the fuzz input
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
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Extract data for API calls
    uint64_t* longArray = (uint64_t*)malloc(sizeof(uint64_t) * 2);
    if (!longArray) {
        freeTIFF(tif);
        return 0;
    }
    memcpy(longArray, data, sizeof(uint64_t) * 2);

    // Call TIFFSwabArrayOfLong8
    TIFFSwabArrayOfLong8(longArray, 2);

    // Call TIFFTileRowSize
    tmsize_t tileRowSize = TIFFTileRowSize(tif);
    if (tileRowSize == 0) {
        free(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Allocate buffer for TIFFWriteRawTile and TIFFReadRawTile
    void* tileBuffer = malloc(tileRowSize);
    if (!tileBuffer) {
        free(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteRawTile
    uint32_t tileIndex = 0; // Assuming tile index 0 for simplicity
    tmsize_t writeSize = TIFFWriteRawTile(tif, tileIndex, tileBuffer, tileRowSize);
    if (writeSize == (tmsize_t)(-1)) {
        free(longArray);
        free(tileBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        free(longArray);
        free(tileBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, tileBuffer, tileRowSize);
    if (readSize == (tmsize_t)(-1)) {
        free(longArray);
        free(tileBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    free(longArray);
    free(tileBuffer);
    freeTIFF(tif);

    return 0;
}
