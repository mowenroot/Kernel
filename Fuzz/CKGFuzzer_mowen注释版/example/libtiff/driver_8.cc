#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object in memory from the fuzz input
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to proceed
    }

    TIFF* tif = createTIFFInMemory(data, size);
    if (tif == NULL) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32_t width = 1024; // Example width
    uint32_t height = 768; // Example height
    uint32_t* raster = (uint32_t*)malloc(width * height * sizeof(uint32_t));
    if (raster == NULL) {
        TIFFClose(tif);
        return 0; // Failed to allocate memory for raster
    }

    // Example usage of TIFFSetField
    if (TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, width) != 1) {
        TIFFError("FuzzDriver", "Failed to set TIFFTAG_IMAGEWIDTH"); // Use TIFFError instead of TIFFErrorExt
    }
    if (TIFFSetField(tif, TIFFTAG_IMAGELENGTH, height) != 1) {
        TIFFError("FuzzDriver", "Failed to set TIFFTAG_IMAGELENGTH"); // Use TIFFError instead of TIFFErrorExt
    }

    // Example usage of TIFFWriteRawTile
    uint32_t tileIndex = 0;
    tmsize_t tileSize = 1024; // Example tile size
    void* tileData = malloc(tileSize);
    if (tileData == NULL) {
        free(raster);
        TIFFClose(tif);
        return 0; // Failed to allocate memory for tile data
    }
    if (TIFFWriteRawTile(tif, tileIndex, tileData, tileSize) == (tmsize_t)(-1)) {
        TIFFError("FuzzDriver", "Failed to write raw tile"); // Use TIFFError instead of TIFFErrorExt
    }
    free(tileData);

    // Example usage of TIFFReadRGBAImageOriented
    int orientation = ORIENTATION_TOPLEFT; // Example orientation
    if (TIFFReadRGBAImageOriented(tif, width, height, raster, orientation, 0) != 1) {
        TIFFError("FuzzDriver", "Failed to read RGBA image"); // Use TIFFError instead of TIFFErrorExt
    }

    // Example usage of TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        TIFFError("FuzzDriver", "Failed to flush data"); // Use TIFFError instead of TIFFErrorExt
    }

    // Example usage of TIFFUnlinkDirectory
    uint16_t dirIndex = 0; // Example directory index
    if (TIFFUnlinkDirectory(tif, dirIndex) != 1) {
        TIFFError("FuzzDriver", "Failed to unlink directory"); // Use TIFFError instead of TIFFErrorExt
    }

    // Clean up
    free(raster);
    TIFFClose(tif);

    return 0;
}
