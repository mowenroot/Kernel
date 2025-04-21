#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from a string
TIFF* CreateTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzz_input = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzz_input);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    tmsize_t tile_size = 1024; // Example size, should be derived from fuzz input
    void* buffer = malloc(tile_size);
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }

    // Example usage of APIs
    int flush_result = TIFFFlushData(tif);
    if (flush_result != 1) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    tmsize_t write_result = TIFFWriteRawTile(tif, tile, buffer, tile_size);
    if (write_result == (tmsize_t)(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    TIFFSetWriteOffset(tif, 0); // Example offset

    tmsize_t read_result = TIFFReadRawTile(tif, tile, buffer, tile_size);
    if (read_result == (tmsize_t)(-1)) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    int rewrite_result = TIFFRewriteDirectory(tif);
    if (rewrite_result != 1) {
        free(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    free(buffer);
    TIFFClose(tif);

    return 0;
}
