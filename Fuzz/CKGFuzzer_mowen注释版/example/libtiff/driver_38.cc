#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object in memory from the fuzz input
TIFF* createTIFFFromInput(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated memory
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a TIFF object from the fuzz input
    TIFF* tif = createTIFFFromInput(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint64_t scanline_size = 0;
    uint32_t tile_index = 0;
    tmsize_t raw_strip_size = 0;
    int exif_dir_result = 0;

    // Extract relevant data from the fuzz input
    uint32_t x = static_cast<uint32_t>(data[0]);
    uint32_t y = static_cast<uint32_t>(data[1]);
    uint32_t z = static_cast<uint32_t>(data[2]);
    uint16_t s = static_cast<uint16_t>(data[3]);
    uint32_t strip = static_cast<uint32_t>(data[4]);

    // Call TIFFScanlineSize64
    scanline_size = TIFFScanlineSize64(tif);
    if (scanline_size == 0) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFComputeTile
    tile_index = TIFFComputeTile(tif, x, y, z, s);
    if (tile_index == 0) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFRawStripSize64
    raw_strip_size = TIFFRawStripSize64(tif, strip);
    if (raw_strip_size == static_cast<tmsize_t>(-1)) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFCreateEXIFDirectory
    exif_dir_result = TIFFCreateEXIFDirectory(tif);
    if (exif_dir_result != 1) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteRawStrip
    // Allocate a buffer for raw data
    uint8_t* raw_data = static_cast<uint8_t*>(malloc(raw_strip_size));
    if (!raw_data) {
        freeTIFF(tif);
        return 0;
    }
    // Fill the buffer with some data (for demonstration purposes)
    memset(raw_data, 0xFF, raw_strip_size);
    tmsize_t write_result = TIFFWriteRawStrip(tif, strip, raw_data, raw_strip_size);
    free(raw_data);
    if (write_result == static_cast<tmsize_t>(-1)) {
        freeTIFF(tif);
        return 0;
    }

    // Free the TIFF object
    freeTIFF(tif);

    return 0;
}
