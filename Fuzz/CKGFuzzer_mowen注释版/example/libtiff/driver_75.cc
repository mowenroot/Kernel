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

// Function to create a TIFF object in memory
TIFF* createTIFFInMemory(const char* data) {
    std::istringstream s(data); // Use std::istringstream instead of tiffio::MemStream
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
    TIFF* tif = createTIFFInMemory(tiffData);
    if (tif == NULL) {
        free(tiffData);
        return 0;
    }

    // Initialize variables
    uint64_t* longArray = (uint64_t*)malloc(sizeof(uint64_t) * 2);
    if (longArray == NULL) {
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }
    longArray[0] = 0x123456789ABCDEF0;
    longArray[1] = 0xFEDCBA9876543210;

    // Call TIFFSwabArrayOfLong8
    TIFFSwabArrayOfLong8(longArray, 2);

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        TIFFClose(tif);
        free(longArray);
        free(tiffData);
        return 0;
    }

    // Call TIFFWriteDirectory
    int writeDirResult = TIFFWriteDirectory(tif);
    if (writeDirResult != 1) {
        TIFFClose(tif);
        free(longArray);
        free(tiffData);
        return 0;
    }

    // Call TIFFFieldReadCount
    const TIFFField* field = TIFFFieldWithTag(tif, TIFFTAG_IMAGEWIDTH);
    if (field == NULL) {
        TIFFClose(tif);
        free(longArray);
        free(tiffData);
        return 0;
    }
    int readCount = TIFFFieldReadCount(field);

    // Call TIFFReadRawTile
    void* tileBuffer = malloc(1024); // Example buffer size
    if (tileBuffer == NULL) {
        TIFFClose(tif);
        free(longArray);
        free(tiffData);
        return 0;
    }
    tmsize_t readTileResult = TIFFReadRawTile(tif, 0, tileBuffer, 1024);
    if (readTileResult == (tmsize_t)(-1)) {
        TIFFClose(tif);
        free(longArray);
        free(tiffData);
        free(tileBuffer);
        return 0;
    }

    // Clean up
    TIFFClose(tif);
    free(longArray);
    free(tiffData);
    free(tileBuffer);

    return 0;
}
