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
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
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
    uint32 tile = 0;
    void* buf = malloc(TIFFTileSize(tif));
    if (buf == NULL) {
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }

    // Call TIFFReadEncodedTile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buf, TIFFTileSize(tif));
    if (readSize == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFWriteEncodedTile
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, buf, readSize);
    if (writeSize == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        // Handle error
    }

    // Call TIFFUnlinkDirectory
    int unlinkResult = TIFFUnlinkDirectory(tif, 1);
    if (unlinkResult == 0) {
        // Handle error
    }

    // Call TIFFSetClientInfo
    void* clientData = (void*)tiffData;
    TIFFSetClientInfo(tif, clientData, "FuzzClientInfo");

    // Clean up
    free(buf);
    TIFFClose(tif);
    free(tiffData);

    return 0;
}
