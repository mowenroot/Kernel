#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include sstream for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory
TIFF* CreateTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
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
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    uint32_t strip = 0;
    tmsize_t cc = 0;
    void* buffer = nullptr;

    // Ensure proper bounds checking
    if (size < sizeof(uint32_t) * 3 + sizeof(tmsize_t)) {
        FreeTIFF(tif);
        return 0;
    }

    // Derive API inputs from fuzz input
    tile = *reinterpret_cast<const uint32_t*>(data);
    strip = *reinterpret_cast<const uint32_t*>(data + sizeof(uint32_t));
    cc = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32_t) * 2);
    buffer = const_cast<void*>(reinterpret_cast<const void*>(data + sizeof(uint32_t) * 3));

    // Call TIFFWriteBufferSetup
    if (!TIFFWriteBufferSetup(tif, nullptr, cc)) {
        FreeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteEncodedTile
    if (TIFFWriteEncodedTile(tif, tile, buffer, cc) == (tmsize_t)(-1)) {
        FreeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteEncodedStrip
    if (TIFFWriteEncodedStrip(tif, strip, buffer, cc) == (tmsize_t)(-1)) {
        FreeTIFF(tif);
        return 0;
    }

    // Call TIFFUnsetField
    if (!TIFFUnsetField(tif, TIFFTAG_IMAGEWIDTH)) {
        FreeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteRawStrip
    if (TIFFWriteRawStrip(tif, strip, buffer, cc) == (tmsize_t)(-1)) {
        FreeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    FreeTIFF(tif);

    return 0;
}
