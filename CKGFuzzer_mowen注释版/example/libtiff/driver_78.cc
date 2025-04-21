#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t *data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* CreateTIFFFromString(const std::string& input) {
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        TIFFErrorExt(0, "CreateTIFFFromString", "Failed to create TIFF from string");
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = FuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = CreateTIFFFromString(input);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tilesize = TIFFTileSize(tif);
    void* buf = malloc(tilesize);
    if (!buf) {
        TIFFClose(tif);
        return 0; // Failed to allocate buffer
    }

    // Call TIFFFieldWithTag and handle errors
    const TIFFField* fieldWithTag = TIFFFieldWithTag(tif, 254); // Example tag
    if (!fieldWithTag) {
        free(buf);
        TIFFClose(tif);
        return 0; // Failed to find field with tag
    }

    // Call TIFFFieldWithName and handle errors
    const TIFFField* fieldWithName = TIFFFieldWithName(tif, "ImageWidth"); // Example field name
    if (!fieldWithName) {
        free(buf);
        TIFFClose(tif);
        return 0; // Failed to find field with name
    }

    // Call TIFFFieldReadCount and handle errors
    int readCount = TIFFFieldReadCount(fieldWithTag);
    if (readCount < 0) {
        free(buf);
        TIFFClose(tif);
        return 0; // Failed to get read count
    }

    // Call TIFFReadRawTile and handle errors
    tmsize_t rawTileSize = TIFFReadRawTile(tif, tile, buf, tilesize);
    if (rawTileSize == (tmsize_t)(-1)) {
        free(buf);
        TIFFClose(tif);
        return 0; // Failed to read raw tile
    }

    // Call TIFFReadEncodedTile and handle errors
    tmsize_t encodedTileSize = TIFFReadEncodedTile(tif, tile, buf, tilesize);
    if (encodedTileSize == (tmsize_t)(-1)) {
        free(buf);
        TIFFClose(tif);
        return 0; // Failed to read encoded tile
    }

    // Clean up
    free(buf);
    TIFFClose(tif);

    return 0;
}
