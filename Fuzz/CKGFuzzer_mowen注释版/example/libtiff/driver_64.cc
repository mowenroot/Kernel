#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const char* data) {
    std::istringstream s(data); // Use std::istringstream instead of std::string
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (tif == NULL) {
        return NULL;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* inputStr = fuzzInputToString(data, size);
    if (inputStr == NULL) {
        return 0;
    }

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(inputStr);
    if (tif == NULL) {
        free(inputStr);
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    uint64_t* longArray = (uint64_t*)malloc(sizeof(uint64_t) * 2);
    if (longArray == NULL) {
        TIFFClose(tif);
        free(inputStr);
        return 0;
    }
    memset(longArray, 0, sizeof(uint64_t) * 2);

    // Derive API inputs from fuzz input
    if (size >= sizeof(uint64_t) * 2) {
        memcpy(longArray, data, sizeof(uint64_t) * 2);
    }

    // Call TIFFSwabArrayOfLong8
    TIFFSwabArrayOfLong8(longArray, 2);

    // Call TIFFCurrentStrip
    uint32_t currentStrip = TIFFCurrentStrip(tif);

    // Call TIFFWriteRawTile
    tmsize_t writeSize = TIFFWriteRawTile(tif, tile, longArray, sizeof(uint64_t) * 2);
    if (writeSize == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFReadRawTile
    tmsize_t readSize = TIFFReadRawTile(tif, tile, longArray, sizeof(uint64_t) * 2);
    if (readSize == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        // Handle error
    }

    // Clean up
    free(longArray);
    TIFFClose(tif);
    free(inputStr);

    return 0;
}
