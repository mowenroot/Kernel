#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t *data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const std::string& data) {
    TIFF* tif = TIFFStreamOpen("MemTIFF", new std::istringstream(data));
    if (!tif) {
        std::cerr << "Failed to create TIFF object in memory" << std::endl;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string tiffData = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(tiffData);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32_t tagValue = 0;
    uint16_t dirNumber = 0;
    uint8_t fillValue = 0;
    tmsize_t fillSize = 0;

    // Ensure we have enough data for basic operations
    if (size < 8) {
        TIFFClose(tif);
        return 0;
    }

    // Derive values from fuzz input
    tagValue = *reinterpret_cast<const uint32_t*>(data);
    dirNumber = *reinterpret_cast<const uint16_t*>(data + 4);
    fillValue = data[6];
    fillSize = *reinterpret_cast<const tmsize_t*>(data + 7);

    // Allocate memory for _TIFFmemset
    void* fillBuffer = malloc(fillSize);
    if (!fillBuffer) {
        TIFFClose(tif);
        return 0; // Memory allocation failed
    }

    // Call _TIFFmemset
    _TIFFmemset(fillBuffer, fillValue, fillSize);

    // Call TIFFSetField
    if (!TIFFSetField(tif, tagValue, fillBuffer)) {
        std::cerr << "TIFFSetField failed" << std::endl;
    }

    // Call TIFFGetField
    if (!TIFFGetField(tif, tagValue, &tagValue)) {
        std::cerr << "TIFFGetField failed" << std::endl;
    }

    // Call TIFFUnlinkDirectory
    if (!TIFFUnlinkDirectory(tif, dirNumber)) {
        std::cerr << "TIFFUnlinkDirectory failed" << std::endl;
    }

    // Call TIFFRewriteDirectory
    if (!TIFFRewriteDirectory(tif)) {
        std::cerr << "TIFFRewriteDirectory failed" << std::endl;
    }

    // Free allocated memory
    free(fillBuffer);

    // Close the TIFF object
    TIFFClose(tif);

    return 0; // Return 0 to indicate success
}
