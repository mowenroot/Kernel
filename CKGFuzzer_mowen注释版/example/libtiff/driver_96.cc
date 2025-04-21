#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory from the fuzz input
TIFF* createTIFFFromFuzzInput(const uint8_t* data, size_t size) {
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 16) return 0;

    // Create a TIFF object from the fuzz input
    TIFF* tif = createTIFFFromFuzzInput(data, size);
    if (!tif) return 0;

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void* tileData = nullptr;
    TIFFRGBAImage img;
    uint32* raster = nullptr;

    // Extract values from fuzz input
    tile = *((uint32*)data);
    tileSize = *((tmsize_t*)(data + 4));
    tileData = (void*)(data + 8);

    // Call TIFFGetSizeProc
    TIFFSizeProc sizeProc = TIFFGetSizeProc(tif);
    if (!sizeProc) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteRawTile
    if (TIFFWriteRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    void* readBuf = malloc(tileSize);
    if (!readBuf) {
        TIFFClose(tif);
        return 0;
    }
    if (TIFFReadRawTile(tif, tile, readBuf, tileSize) == (tmsize_t)(-1)) {
        free(readBuf);
        TIFFClose(tif);
        return 0;
    }
    free(readBuf);

    // Call TIFFRGBAImageGet
    if (TIFFRGBAImageBegin(&img, tif, 0, nullptr) != 1) {
        TIFFClose(tif);
        return 0;
    }
    raster = (uint32*)malloc(img.width * img.height * sizeof(uint32));
    if (!raster) {
        TIFFRGBAImageEnd(&img);
        TIFFClose(tif);
        return 0;
    }
    if (TIFFRGBAImageGet(&img, raster, img.width, img.height) != 1) {
        free(raster);
        TIFFRGBAImageEnd(&img);
        TIFFClose(tif);
        return 0;
    }
    free(raster);
    TIFFRGBAImageEnd(&img);

    // Close the TIFF object
    TIFFClose(tif);

    return 0;
}
