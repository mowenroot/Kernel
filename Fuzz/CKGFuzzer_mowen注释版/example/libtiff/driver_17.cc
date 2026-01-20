#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to handle memory allocation failure
void handleMemoryAllocationFailure() {
    fprintf(stderr, "Memory allocation failed\n");
    exit(1);
}

// Function to handle TIFF errors
void handleTiffError(const char* module, const char* fmt, va_list ap) {
    fprintf(stderr, "TIFF Error in %s: ", module);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

// Function to handle TIFF warnings
void handleTiffWarning(const char* module, const char* fmt, va_list ap) {
    fprintf(stderr, "TIFF Warning in %s: ", module);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize TIFF error handlers
    TIFFSetErrorHandler(handleTiffError);
    TIFFSetWarningHandler(handleTiffWarning);

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32_t) * 3) {
        return 0;
    }

    // Convert fuzz input to a string
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
    if (!tif) {
        return 0;
    }

    // Extract necessary parameters from the fuzz input
    uint32_t tile = *((uint32_t*)data);
    uint32_t stripSize = *((uint32_t*)(data + sizeof(uint32_t)));
    uint32_t customDirOffset = *((uint32_t*)(data + 2 * sizeof(uint32_t)));

    // Ensure the tile index is within a reasonable range
    if (tile >= 1000) {
        TIFFClose(tif);
        return 0;
    }

    // Allocate memory for the tile data
    void* tileData = malloc(stripSize);
    if (!tileData) {
        handleMemoryAllocationFailure();
    }

    // Initialize tile data with a portion of the fuzz input
    memcpy(tileData, data + 3 * sizeof(uint32_t), stripSize);

    // Call TIFFWriteRawTile
    tmsize_t bytesWritten = TIFFWriteRawTile(tif, tile, tileData, stripSize);
    if (bytesWritten == (tmsize_t)(-1)) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFStripSize
    tmsize_t stripSizeResult = TIFFStripSize(tif);
    if (stripSizeResult == 0) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t bytesRead = TIFFReadRawTile(tif, tile, tileData, stripSize);
    if (bytesRead == (tmsize_t)(-1)) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadCustomDirectory
    int customDirResult = TIFFReadCustomDirectory(tif, customDirOffset, NULL);
    if (!customDirResult) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadDirectory
    int readDirResult = TIFFReadDirectory(tif);
    if (!readDirResult) {
        free(tileData);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated memory and close the TIFF object
    free(tileData);
    TIFFClose(tif);

    return 0;
}
