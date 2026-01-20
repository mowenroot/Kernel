#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    char emsg[1024] = {0};
    uint32 tw = 0, th = 0;
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void* tileData = nullptr;

    // Initialize the TIFF object in memory
    tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA format
    if (TIFFRGBAImageOK(tif, emsg)) {
        // If the image is OK, proceed with other operations

        // Call TIFFDefaultTileSize to get default tile dimensions
        TIFFDefaultTileSize(tif, &tw, &th);

        // Call TIFFFlushData to ensure data integrity
        if (TIFFFlushData(tif) != 1) {
            freeTIFF(tif);
            return 0;
        }

        // Allocate memory for tile data
        tileSize = tw * th * sizeof(uint32);
        tileData = malloc(tileSize);
        if (!tileData) {
            freeTIFF(tif);
            return 0;
        }

        // Call TIFFReadRawTile to read raw tile data
        tile = 0; // Assuming tile index 0 for simplicity
        if (TIFFReadRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
            free(tileData);
            freeTIFF(tif);
            return 0;
        }

        // Call TIFFWriteRawTile to write raw tile data
        if (TIFFWriteRawTile(tif, tile, tileData, tileSize) == (tmsize_t)(-1)) {
            free(tileData);
            freeTIFF(tif);
            return 0;
        }

        // Free allocated memory
        free(tileData);
    }

    // Free the TIFF object
    freeTIFF(tif);

    return 0;
}
