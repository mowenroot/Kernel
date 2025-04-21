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

// Function to create a TIFF object from a string
TIFF* CreateTIFFFromString(const std::string& input) {
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
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

    // Create a TIFF object from the string
    TIFF* tif = CreateTIFFFromString(input);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    tmsize_t tileSize = TIFFTileSize64(tif);
    if (tileSize == 0) {
        FreeTIFF(tif);
        return 0;
    }

    // Allocate buffer for tile operations
    void* buf = _TIFFmalloc(tileSize);
    if (!buf) {
        FreeTIFF(tif);
        return 0;
    }

    // Set client info
    TIFFSetClientInfo(tif, buf, "FuzzClient");

    // Perform tile operations
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buf, tileSize);
    if (readSize == (tmsize_t)(-1)) {
        _TIFFfree(buf);
        FreeTIFF(tif);
        return 0;
    }

    tmsize_t writeSize = TIFFWriteRawTile(tif, tile, buf, readSize);
    if (writeSize == (tmsize_t)(-1)) {
        _TIFFfree(buf);
        FreeTIFF(tif);
        return 0;
    }

    tmsize_t rawReadSize = TIFFReadRawTile(tif, tile, buf, tileSize);
    if (rawReadSize == (tmsize_t)(-1)) {
        _TIFFfree(buf);
        FreeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    _TIFFfree(buf);
    FreeTIFF(tif);

    return 0;
}
