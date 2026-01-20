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

// Function to create a TIFF object from a string
TIFF* CreateTIFFFromString(const std::string& input) {
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
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

    // Create a TIFF object from the string
    TIFF* tif = CreateTIFFFromString(input);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Variables for API calls
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void* buffer = nullptr;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size < sizeof(uint32)) {
        FreeTIFF(tif);
        return 0; // Insufficient data
    }

    // Derive tile index from fuzz input
    memcpy(&tile, data, sizeof(uint32));
    tile %= 100; // Arbitrary limit to avoid out-of-bounds issues

    // Derive tile size from fuzz input
    if (size >= sizeof(uint32) + sizeof(tmsize_t)) {
        memcpy(&tileSize, data + sizeof(uint32), sizeof(tmsize_t));
    } else {
        tileSize = 1024; // Default tile size
    }

    // Allocate buffer for tile data
    buffer = malloc(tileSize);
    if (!buffer) {
        FreeTIFF(tif);
        return 0; // Allocation failed
    }

    // Call TIFFFileno
    int fd = TIFFFileno(tif);
    if (fd < 0) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Invalid file descriptor
    }

    // Call TIFFReadEncodedTile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buffer, tileSize);
    if (readSize == (tmsize_t)(-1)) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Read failed
    }

    // Call TIFFWriteRawTile
    tmsize_t writeSize = TIFFWriteRawTile(tif, tile, buffer, readSize);
    if (writeSize == (tmsize_t)(-1)) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Write failed
    }

    // Call TIFFReadRawTile
    tmsize_t rawReadSize = TIFFReadRawTile(tif, tile, buffer, tileSize);
    if (rawReadSize == (tmsize_t)(-1)) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Raw read failed
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Flush failed
    }

    // Free allocated resources
    free(buffer);
    FreeTIFF(tif);

    return 0; // Success
}
