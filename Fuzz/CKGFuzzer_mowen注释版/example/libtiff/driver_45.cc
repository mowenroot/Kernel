#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include sstream for std::istringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        fprintf(stderr, "Failed to create TIFF object in memory\n");
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    uint32_t strip = 0;
    tmsize_t cc = size;
    void* buffer = malloc(cc);
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }
    memcpy(buffer, data, cc);

    // Call TIFFWriteCheck to ensure the TIFF file is ready for writing
    if (TIFFWriteCheck(tif, 1, "FuzzDriver") != 1) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteEncodedTile
    if (TIFFWriteEncodedTile(tif, tile, buffer, cc) == (tmsize_t)(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteRawTile
    if (TIFFWriteRawTile(tif, tile, buffer, cc) == (tmsize_t)(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteEncodedStrip
    if (TIFFWriteEncodedStrip(tif, strip, buffer, cc) == (tmsize_t)(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteRawStrip
    if (TIFFWriteRawStrip(tif, strip, buffer, cc) == (tmsize_t)(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteDirectory
    if (TIFFWriteDirectory(tif) != 1) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated resources
    free(buffer);
    TIFFClose(tif);

    return 0;
}
