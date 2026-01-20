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
TIFF* createTIFFInMemory(const char* str) {
    std::istringstream s(str); // Use std::istringstream instead of std::string
    return TIFFStreamOpen("mem", &s); // Pass the address of the istringstream
}

// Fuzz driver function
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
    uint32 tile = 0;
    tmsize_t tileSize = TIFFTileSize(tif);
    void* buf = malloc(tileSize);
    if (buf == NULL) {
        TIFFClose(tif);
        free(inputStr);
        return 0;
    }

    // Call TIFFCreateDirectory
    if (TIFFCreateDirectory(tif) != 0) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFCreateDirectory failed"); // Use 0 instead of tif->tif_clientdata
        TIFFClose(tif);
        free(buf);
        free(inputStr);
        return 0;
    }

    // Call TIFFWriteEncodedTile
    if (TIFFWriteEncodedTile(tif, tile, buf, tileSize) == (tmsize_t)(-1)) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFWriteEncodedTile failed"); // Use 0 instead of tif->tif_clientdata
        TIFFClose(tif);
        free(buf);
        free(inputStr);
        return 0;
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFFlushData failed"); // Use 0 instead of tif->tif_clientdata
        TIFFClose(tif);
        free(buf);
        free(inputStr);
        return 0;
    }

    // Call TIFFReadEncodedTile
    if (TIFFReadEncodedTile(tif, tile, buf, tileSize) == (tmsize_t)(-1)) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFReadEncodedTile failed"); // Use 0 instead of tif->tif_clientdata
        TIFFClose(tif);
        free(buf);
        free(inputStr);
        return 0;
    }

    // Call TIFFUnlinkDirectory
    if (TIFFUnlinkDirectory(tif, 1) != 1) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFUnlinkDirectory failed"); // Use 0 instead of tif->tif_clientdata
        TIFFClose(tif);
        free(buf);
        free(inputStr);
        return 0;
    }

    // Clean up
    TIFFClose(tif);
    free(buf);
    free(inputStr);

    return 0;
}
