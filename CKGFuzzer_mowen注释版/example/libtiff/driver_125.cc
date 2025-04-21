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
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Function to free the TIFF object and associated memory
void FreeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
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
    void* buf = nullptr;
    tmsize_t bufSize = 0;
    toff_t diroff = 0;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size >= sizeof(uint32)) {
        tile = *reinterpret_cast<const uint32*>(data);
    }
    if (size >= sizeof(tmsize_t)) {
        bufSize = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32));
    }
    if (size >= sizeof(toff_t)) {
        diroff = *reinterpret_cast<const toff_t*>(data + sizeof(uint32) + sizeof(tmsize_t));
    }

    // Allocate memory for the buffer
    buf = malloc(bufSize);
    if (!buf) {
        FreeTIFF(tif);
        return 0; // Failed to allocate memory
    }

    // Call TIFFSetField to set a TIFF tag
    if (TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 1024) != 1) {
        free(buf);
        FreeTIFF(tif);
        return 0; // Failed to set TIFF field
    }

    // Call TIFFReadEXIFDirectory to read EXIF metadata
    if (TIFFReadEXIFDirectory(tif, diroff) != 1) {
        free(buf);
        FreeTIFF(tif);
        return 0; // Failed to read EXIF directory
    }

    // Call TIFFReadRawTile to read raw tile data
    if (TIFFReadRawTile(tif, tile, buf, bufSize) == (tmsize_t)(-1)) {
        free(buf);
        FreeTIFF(tif);
        return 0; // Failed to read raw tile
    }

    // Call TIFFReadEncodedTile to read and decode a tile
    if (TIFFReadEncodedTile(tif, tile, buf, bufSize) == (tmsize_t)(-1)) {
        free(buf);
        FreeTIFF(tif);
        return 0; // Failed to read encoded tile
    }

    // Call TIFFFlushData to flush buffered data
    if (TIFFFlushData(tif) != 1) {
        free(buf);
        FreeTIFF(tif);
        return 0; // Failed to flush data
    }

    // Free allocated resources
    free(buf);
    FreeTIFF(tif);

    return 0; // Success
}
