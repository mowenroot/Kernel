#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from the fuzz input
TIFF* CreateTIFFInMemory(const uint8_t* data, size_t size) {
    std::string input = FuzzInputToString(data, size);
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Function to free the TIFF object and associated memory
void FreeTIFFInMemory(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    TIFFRGBAImage img;
    uint32* raster = nullptr;
    tmsize_t rasterSize = 0;
    tmsize_t tileSize = 0;
    uint32 tileIndex = 0;
    uint32 width = 0, height = 0;
    int result = 0;

    // Initialize variables to avoid undefined behavior
    memset(&img, 0, sizeof(img));

    // Create a TIFF object in memory from the fuzz input
    tif = CreateTIFFInMemory(data, size);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Example usage of TIFFRasterScanlineSize
    rasterSize = TIFFRasterScanlineSize(tif);
    if (rasterSize == 0) {
        FreeTIFFInMemory(tif);
        return 0; // Error in calculating raster scanline size
    }

    // Example usage of TIFFWriteRawTile
    tileSize = size / 2; // Use half of the input size as tile size
    tileIndex = 0; // Assume tile index 0 for simplicity
    if (TIFFWriteRawTile(tif, tileIndex, const_cast<uint8_t*>(data), tileSize) == (tmsize_t)(-1)) {
        FreeTIFFInMemory(tif);
        return 0; // Error in writing raw tile
    }

    // Example usage of TIFFFlushData
    if (TIFFFlushData(tif) == 0) {
        FreeTIFFInMemory(tif);
        return 0; // Error in flushing data
    }

    // Example usage of TIFFReadRawTile
    uint8_t* readBuffer = static_cast<uint8_t*>(malloc(tileSize));
    if (!readBuffer) {
        FreeTIFFInMemory(tif);
        return 0; // Memory allocation failed
    }
    if (TIFFReadRawTile(tif, tileIndex, readBuffer, tileSize) == (tmsize_t)(-1)) {
        free(readBuffer);
        FreeTIFFInMemory(tif);
        return 0; // Error in reading raw tile
    }
    free(readBuffer);

    // Example usage of TIFFRGBAImageGet
    width = 1024; // Example width
    height = 768; // Example height
    raster = static_cast<uint32*>(malloc(width * height * sizeof(uint32)));
    if (!raster) {
        FreeTIFFInMemory(tif);
        return 0; // Memory allocation failed
    }
    if (TIFFRGBAImageBegin(&img, tif, 0, nullptr) != 1) {
        free(raster);
        FreeTIFFInMemory(tif);
        return 0; // Error in beginning RGBA image
    }
    result = TIFFRGBAImageGet(&img, raster, width, height);
    TIFFRGBAImageEnd(&img);
    free(raster);

    // Free the TIFF object and associated memory
    FreeTIFFInMemory(tif);

    return result;
}
