#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream
#include <cassert>

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* CreateTIFFFromString(const std::string& input) {
    // Create a TIFF object in memory
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    assert(tif != nullptr);
    return tif;
}

// Function to free the TIFF object and associated resources
void FreeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = FuzzInputToString(data, size);

    // Create a TIFF object from the input string
    TIFF* tif = CreateTIFFFromString(input);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32 tile = 0;
    void* buf = nullptr;
    tmsize_t buf_size = 0;
    uint32 tag = 0;
    uint32 tag_entry = 0;
    int result = 0;

    // Call TIFFSetClientInfo
    TIFFSetClientInfo(tif, nullptr, "FuzzClient");

    // Call TIFFGetTagListEntry
    tag_entry = TIFFGetTagListEntry(tif, 0);
    if (tag_entry == static_cast<uint32>(-1)) {
        FreeTIFF(tif);
        return 0; // Invalid tag entry
    }

    // Call TIFFVGetFieldDefaulted
    result = TIFFVGetFieldDefaulted(tif, tag_entry, nullptr);
    if (result != 1) {
        FreeTIFF(tif);
        return 0; // Failed to get field defaulted
    }

    // Allocate buffer for TIFFReadRawTile
    buf_size = TIFFTileSize(tif);
    if (buf_size <= 0) {
        FreeTIFF(tif);
        return 0; // Invalid buffer size
    }
    buf = malloc(buf_size);
    if (!buf) {
        FreeTIFF(tif);
        return 0; // Failed to allocate buffer
    }

    // Call TIFFReadRawTile
    tmsize_t bytes_read = TIFFReadRawTile(tif, tile, buf, buf_size);
    if (bytes_read == static_cast<tmsize_t>(-1)) {
        free(buf);
        FreeTIFF(tif);
        return 0; // Failed to read raw tile
    }

    // Call TIFFRewriteDirectory
    result = TIFFRewriteDirectory(tif);
    if (result != 1) {
        free(buf);
        FreeTIFF(tif);
        return 0; // Failed to rewrite directory
    }

    // Free allocated resources
    free(buf);
    FreeTIFF(tif);

    return 0; // Success
}
