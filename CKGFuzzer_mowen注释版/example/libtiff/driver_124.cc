#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object from fuzz input data
TIFF* createTIFFFromFuzzInput(const uint8_t* data, size_t size) {
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

// Function to free the TIFF object and associated resources
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    uint32 tile = 0;
    void* buf = nullptr;
    tmsize_t buf_size = 0;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32) + sizeof(tmsize_t)) {
        return 0;
    }

    // Create a TIFF object from the fuzz input data
    tif = createTIFFFromFuzzInput(data, size);
    if (!tif) {
        return 0;
    }

    // Extract tile index and buffer size from the fuzz input
    tile = *((uint32*)(data + size - sizeof(uint32)));
    buf_size = *((tmsize_t*)(data + size - sizeof(uint32) - sizeof(tmsize_t)));

    // Allocate buffer for reading/writing tile data
    buf = malloc(buf_size);
    if (!buf) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFFlushData to ensure data integrity
    if (TIFFFlushData(tif) != 1) {
        // Handle error
    }

    // Call TIFFWriteRawTile to write raw tile data
    if (TIFFWriteRawTile(tif, tile, buf, buf_size) == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFReadRawTile to read raw tile data
    if (TIFFReadRawTile(tif, tile, buf, buf_size) == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFRewriteDirectory to rewrite the directory
    if (TIFFRewriteDirectory(tif) != 1) {
        // Handle error
    }

    // Call TIFFReadDirectory to read and process directory entries
    if (TIFFReadDirectory(tif) != 1) {
        // Handle error
    }

    // Free allocated resources
    free(buf);
    freeTIFF(tif);

    return 0;
}
