#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

// Function to free the allocated string
void freeFuzzInputString(char* str) {
    free(str);
}

// Function to allocate memory for tile data
void* allocateTileData(tmsize_t size) {
    return malloc(size);
}

// Function to free allocated tile data
void freeTileData(void* data) {
    free(data);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* fuzzInput = fuzzInputToString(data, size);
    if (fuzzInput == NULL) {
        return 0;
    }

    // Open a TIFF file in memory
    TIFF* tif = TIFFClientOpen(
        fuzzInput, "w",
        0, // clientdata
        NULL, // readproc
        NULL, // writeproc
        NULL, // seekproc
        NULL, // closeproc
        NULL, // sizeproc
        NULL, // mapproc
        NULL  // unmapproc
    );
    if (tif == NULL) {
        freeFuzzInputString(fuzzInput);
        return 0;
    }

    // Allocate memory for tile data
    tmsize_t tileSize = 1024; // Example size, should be derived from TIFF metadata
    void* tileData = allocateTileData(tileSize);
    if (tileData == NULL) {
        TIFFClose(tif);
        freeFuzzInputString(fuzzInput);
        return 0;
    }

    // Write raw tile data
    uint32 tileIndex = 0; // Example index, should be derived from fuzz input
    tmsize_t bytesWritten = TIFFWriteRawTile(tif, tileIndex, tileData, tileSize);
    if (bytesWritten == (tmsize_t)(-1)) {
        freeTileData(tileData);
        TIFFClose(tif);
        freeFuzzInputString(fuzzInput);
        return 0;
    }

    // Flush data to ensure it's written
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        freeTileData(tileData);
        TIFFClose(tif);
        freeFuzzInputString(fuzzInput);
        return 0;
    }

    // Read raw tile data
    void* readBuffer = allocateTileData(tileSize);
    if (readBuffer == NULL) {
        freeTileData(tileData);
        TIFFClose(tif);
        freeFuzzInputString(fuzzInput);
        return 0;
    }

    tmsize_t bytesRead = TIFFReadRawTile(tif, tileIndex, readBuffer, tileSize);
    if (bytesRead == (tmsize_t)(-1)) {
        freeTileData(tileData);
        freeTileData(readBuffer);
        TIFFClose(tif);
        freeFuzzInputString(fuzzInput);
        return 0;
    }

    // Unlink a directory
    uint16 dirIndex = 0; // Example index, should be derived from fuzz input
    int unlinkResult = TIFFUnlinkDirectory(tif, dirIndex);
    if (unlinkResult == 0) {
        freeTileData(tileData);
        freeTileData(readBuffer);
        TIFFClose(tif);
        freeFuzzInputString(fuzzInput);
        return 0;
    }

    // Free allocated resources
    freeTileData(tileData);
    freeTileData(readBuffer);
    TIFFClose(tif);
    freeFuzzInputString(fuzzInput);

    return 0;
}
