#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFFromString(const char* str) {
    std::istringstream s(str); // Use std::istringstream instead of std::string
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        TIFFErrorExt(0, "createTIFFFromString", "Failed to create TIFF object from string");
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* tiffData = fuzzInputToString(data, size);
    if (!tiffData) return 0;

    // Create a TIFF object in memory
    TIFF* tif = createTIFFFromString(tiffData);
    if (!tif) {
        free(tiffData);
        return 0;
    }

    // Initialize variables
    uint64_t* longArray = nullptr;
    tmsize_t longArraySize = 0;
    uint32 tileIndex = 0;
    void* tileBuffer = nullptr;
    tmsize_t tileBufferSize = 0;
    int reversed = 0;
    toff_t customDirOffset = 0;
    const TIFFFieldArray* customFieldArray = nullptr;

    // Extract inputs from fuzz data
    if (size >= sizeof(uint64_t) + sizeof(uint32) + sizeof(int) + sizeof(toff_t)) {
        longArraySize = size / sizeof(uint64_t);
        longArray = (uint64_t*)malloc(longArraySize * sizeof(uint64_t));
        if (longArray) {
            memcpy(longArray, data, longArraySize * sizeof(uint64_t));
        }

        tileIndex = *(uint32*)(data + longArraySize * sizeof(uint64_t));
        reversed = *(int*)(data + longArraySize * sizeof(uint64_t) + sizeof(uint32));
        customDirOffset = *(toff_t*)(data + longArraySize * sizeof(uint64_t) + sizeof(uint32) + sizeof(int));
    }

    // Call TIFFSwabArrayOfLong8
    if (longArray) {
        TIFFSwabArrayOfLong8(longArray, longArraySize);
    }

    // Call TIFFCurrentDirectory
    uint16 currentDir = TIFFCurrentDirectory(tif);
    (void)currentDir; // Suppress unused variable warning

    // Call TIFFReadRawTile
    if (size >= sizeof(uint64_t) + sizeof(uint32) + sizeof(int) + sizeof(toff_t) + sizeof(tmsize_t)) {
        tileBufferSize = *(tmsize_t*)(data + longArraySize * sizeof(uint64_t) + sizeof(uint32) + sizeof(int) + sizeof(toff_t));
        tileBuffer = malloc(tileBufferSize);
        if (tileBuffer) {
            tmsize_t bytesRead = TIFFReadRawTile(tif, tileIndex, tileBuffer, tileBufferSize);
            if (bytesRead == (tmsize_t)(-1)) {
                TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFReadRawTile failed");
            }
        }
    }

    // Call TIFFGetBitRevTable
    const unsigned char* bitRevTable = TIFFGetBitRevTable(reversed);
    (void)bitRevTable; // Suppress unused variable warning

    // Call TIFFReadCustomDirectory
    int customDirResult = TIFFReadCustomDirectory(tif, customDirOffset, customFieldArray);
    if (!customDirResult) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFReadCustomDirectory failed");
    }

    // Clean up
    if (longArray) free(longArray);
    if (tileBuffer) free(tileBuffer);
    TIFFClose(tif);
    free(tiffData);

    return 0;
}
