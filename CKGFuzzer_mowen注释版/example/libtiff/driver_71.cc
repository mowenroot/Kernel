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

// Function to create a TIFFRGBAImage object
TIFFRGBAImage* createTIFFRGBAImage(TIFF* tif) {
    TIFFRGBAImage* img = (TIFFRGBAImage*)malloc(sizeof(TIFFRGBAImage));
    if (img == NULL) {
        return NULL;
    }
    char emsg[1024]; // Declare a buffer for error messages
    if (TIFFRGBAImageOK(tif, emsg) != 1) { // Use the correct function signature
        free(img);
        return NULL;
    }
    return img;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient
    if (size < 16) {
        return 0;
    }

    // Convert fuzz input to a string
    char* filename = fuzzInputToString(data, size);
    if (filename == NULL) {
        return 0;
    }

    // Open the TIFF file descriptor
    TIFF* tif = TIFFFdOpen(0, filename, "r");
    if (tif == NULL) {
        free(filename);
        return 0;
    }

    // Create a TIFFRGBAImage object
    TIFFRGBAImage* img = createTIFFRGBAImage(tif);
    if (img == NULL) {
        TIFFClose(tif);
        free(filename);
        return 0;
    }

    // Allocate buffer for raw tile data
    uint32_t tileIndex = data[0];
    uint32_t tileSize = data[1];
    void* tileBuffer = malloc(tileSize);
    if (tileBuffer == NULL) {
        TIFFRGBAImageEnd(img);
        TIFFClose(tif);
        free(filename);
        return 0;
    }

    // Read raw tile data
    tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, tileBuffer, tileSize);
    if (readSize == (tmsize_t)(-1)) {
        free(tileBuffer);
        TIFFRGBAImageEnd(img);
        TIFFClose(tif);
        free(filename);
        return 0;
    }

    // Allocate buffer for RGBA image data
    uint32_t width = data[2];
    uint32_t height = data[3];
    uint32_t* raster = (uint32_t*)malloc(width * height * sizeof(uint32_t));
    if (raster == NULL) {
        free(tileBuffer);
        TIFFRGBAImageEnd(img);
        TIFFClose(tif);
        free(filename);
        return 0;
    }

    // Get RGBA image data
    int result = TIFFRGBAImageGet(img, raster, width, height);
    if (result != 1) {
        free(raster);
        free(tileBuffer);
        TIFFRGBAImageEnd(img);
        TIFFClose(tif);
        free(filename);
        return 0;
    }

    // Flush data to ensure consistency
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        free(raster);
        free(tileBuffer);
        TIFFRGBAImageEnd(img);
        TIFFClose(tif);
        free(filename);
        return 0;
    }

    // Clean up
    free(raster);
    free(tileBuffer);
    TIFFRGBAImageEnd(img);
    TIFFClose(tif);
    free(filename);

    return 0;
}
