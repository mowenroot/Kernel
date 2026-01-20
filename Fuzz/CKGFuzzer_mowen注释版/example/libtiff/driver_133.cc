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

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const char* str) {
    std::istringstream s(str); // Use std::istringstream to match TIFFStreamOpen's expected type
    return TIFFStreamOpen("memory", &s);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* tiffData = fuzzInputToString(data, size);
    if (tiffData == NULL) {
        return 0;
    }

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(tiffData);
    if (tif == NULL) {
        free(tiffData);
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    void* buf = malloc(size);
    if (buf == NULL) {
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t readSize = TIFFReadRawTile(tif, tile, buf, size);
    if (readSize == (tmsize_t)(-1)) {
        free(buf);
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }

    // Call TIFFUnlinkDirectory
    uint16 dirn = 1; // Example directory number
    int unlinkResult = TIFFUnlinkDirectory(tif, dirn);
    if (unlinkResult == 0) {
        free(buf);
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }

    // Call TIFFSetClientInfo
    void* clientData = (void*)data;
    const char* clientName = "FuzzClient";
    TIFFSetClientInfo(tif, clientData, clientName);

    // Call TIFFFlush
    int flushResult = TIFFFlush(tif);
    if (flushResult == 0) {
        free(buf);
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }

    // Call TIFFReadRGBATileExt
    uint32 col = 0;
    uint32 row = 0;
    uint32* raster = (uint32*)malloc(size * sizeof(uint32));
    if (raster == NULL) {
        free(buf);
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }
    int readRGBAExtResult = TIFFReadRGBATileExt(tif, col, row, raster, 1);
    if (readRGBAExtResult == 0) {
        free(buf);
        free(raster);
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }

    // Clean up
    free(buf);
    free(raster);
    TIFFClose(tif);
    free(tiffData);

    return 0;
}
