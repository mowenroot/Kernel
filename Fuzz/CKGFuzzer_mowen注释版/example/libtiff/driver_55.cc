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

// Function to create a TIFF object in memory from the fuzz input string
TIFF* createTIFFInMemory(const char* data) {
    std::istringstream s(data); // Use std::istringstream to wrap the data
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (tif == NULL) {
        return NULL;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* fuzzInput = fuzzInputToString(data, size);
    if (fuzzInput == NULL) {
        return 0;
    }

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzInput);
    if (tif == NULL) {
        free(fuzzInput);
        return 0;
    }

    // Initialize variables
    uint32 tileIndex = 0;
    tmsize_t tileSize = 1024; // Example size, should be derived from the fuzz input
    void* tileBuffer = _TIFFmalloc(tileSize); // Use _TIFFmalloc instead of _TIFFCheckMalloc
    if (tileBuffer == NULL) {
        TIFFClose(tif);
        free(fuzzInput);
        return 0;
    }

    // Call TIFFWriteRawTile
    tmsize_t writeResult = TIFFWriteRawTile(tif, tileIndex, tileBuffer, tileSize);
    if (writeResult == (tmsize_t)(-1)) {
        _TIFFfree(tileBuffer);
        TIFFClose(tif);
        free(fuzzInput);
        return 0;
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        _TIFFfree(tileBuffer);
        TIFFClose(tif);
        free(fuzzInput);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t readResult = TIFFReadRawTile(tif, tileIndex, tileBuffer, tileSize);
    if (readResult == (tmsize_t)(-1)) {
        _TIFFfree(tileBuffer);
        TIFFClose(tif);
        free(fuzzInput);
        return 0;
    }

    // Create a TIFFRGBAImage structure
    TIFFRGBAImage img;
    memset(&img, 0, sizeof(TIFFRGBAImage));
    img.tif = tif;

    // Call TIFFRGBAImageGet
    uint32* raster = (uint32*)_TIFFmalloc(tileSize * sizeof(uint32)); // Use _TIFFmalloc instead of _TIFFCheckMalloc
    if (raster == NULL) {
        _TIFFfree(tileBuffer);
        TIFFClose(tif);
        free(fuzzInput);
        return 0;
    }
    int rgbaResult = TIFFRGBAImageGet(&img, raster, tileSize, tileSize);
    if (rgbaResult == 0) {
        _TIFFfree(raster);
        _TIFFfree(tileBuffer);
        TIFFClose(tif);
        free(fuzzInput);
        return 0;
    }

    // Free allocated resources
    _TIFFfree(raster);
    _TIFFfree(tileBuffer);
    TIFFClose(tif);
    free(fuzzInput);

    return 0;
}
