#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const std::string& input) {
    std::istringstream s(input); // Create an in-memory stream from the string
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Function to free the TIFF object and associated memory
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        // Not enough data to perform meaningful operations
        return 0;
    }

    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(input);
    if (!tif) {
        return 0;
    }

    // Extract necessary data from the fuzz input
    uint32 tile = *reinterpret_cast<const uint32*>(data);
    uint64* tileData = reinterpret_cast<uint64*>(malloc(size - 4));
    if (!tileData) {
        freeTIFF(tif);
        return 0;
    }
    memcpy(tileData, data + 4, size - 4);

    // Perform TIFFSwabArrayOfLong8
    TIFFSwabArrayOfLong8(tileData, (size - 4) / sizeof(uint64));

    // Perform TIFFReadEncodedTile
    void* readBuffer = malloc(size - 4);
    if (!readBuffer) {
        free(tileData);
        freeTIFF(tif);
        return 0;
    }
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, readBuffer, size - 4);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(tileData);
        free(readBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Perform TIFFWriteEncodedTile
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, tileData, size - 4);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        free(tileData);
        free(readBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Perform TIFFGetBitRevTable
    const unsigned char* bitRevTable = TIFFGetBitRevTable(1);
    if (!bitRevTable) {
        free(tileData);
        free(readBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Perform TIFFFlush
    int flushResult = TIFFFlush(tif);
    if (flushResult == 0) {
        free(tileData);
        free(readBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    free(tileData);
    free(readBuffer);
    freeTIFF(tif);

    return 0;
}
