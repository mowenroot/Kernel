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
TIFF* createTIFFFromString(const char* str) {
    std::istringstream s(str); // Use std::istringstream instead of passing a raw string
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (tif == NULL) {
        return NULL;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* tiffData = fuzzInputToString(data, size);
    if (tiffData == NULL) {
        return 0;
    }

    // Create a TIFF object in memory
    TIFF* tif = createTIFFFromString(tiffData);
    if (tif == NULL) {
        free(tiffData);
        return 0;
    }

    // Initialize variables
    uint64_t* longArray = NULL;
    tmsize_t longArraySize = 0;
    uint32_t tileIndex = 0;
    void* tileBuffer = NULL;
    tmsize_t tileBufferSize = 0;
    uint16_t dirIndex = 0;
    void* clientData = NULL;
    const char* clientName = "FuzzClient";

    // Derive inputs from fuzz data
    if (size >= sizeof(uint64_t) * 2) {
        longArraySize = size / sizeof(uint64_t);
        longArray = (uint64_t*)malloc(longArraySize * sizeof(uint64_t));
        if (longArray != NULL) {
            memcpy(longArray, data, longArraySize * sizeof(uint64_t));
        }
    }

    if (size >= sizeof(uint32_t)) {
        tileIndex = *((uint32_t*)data);
    }

    if (size >= sizeof(tmsize_t)) {
        tileBufferSize = *((tmsize_t*)data);
        tileBuffer = malloc(tileBufferSize);
    }

    if (size >= sizeof(uint16_t)) {
        dirIndex = *((uint16_t*)data);
    }

    if (size >= sizeof(void*)) {
        clientData = (void*)data;
    }

    // Call TIFFSwabArrayOfLong8
    if (longArray != NULL) {
        TIFFSwabArrayOfLong8(longArray, longArraySize);
    }

    // Call TIFFReadRawTile
    if (tileBuffer != NULL) {
        TIFFReadRawTile(tif, tileIndex, tileBuffer, tileBufferSize);
    }

    // Call TIFFUnlinkDirectory
    TIFFUnlinkDirectory(tif, dirIndex);

    // Call TIFFSetClientInfo
    TIFFSetClientInfo(tif, clientData, clientName);

    // Cleanup
    TIFFCleanup(tif);
    free(tiffData);
    free(longArray);
    free(tileBuffer);

    return 0;
}
