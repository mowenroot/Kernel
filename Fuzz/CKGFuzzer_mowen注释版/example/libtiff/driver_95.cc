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

// Function to create a TIFF object in memory from a string
TIFF* CreateTIFFFromString(const std::string& input) {
    // Create a TIFF object in memory
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
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

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFFromString(input);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    int result = 0;
    tmsize_t bufferSize = size > 0 ? static_cast<tmsize_t>(size) : 8192; // Default buffer size
    void* buffer = malloc(bufferSize);
    if (!buffer) {
        FreeTIFF(tif);
        return 0; // Failed to allocate buffer
    }

    // Setup read buffer
    if (TIFFReadBufferSetup(tif, buffer, bufferSize) != 1) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to setup read buffer
    }

    // Setup write buffer
    if (TIFFWriteBufferSetup(tif, buffer, bufferSize) != 1) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to setup write buffer
    }

    // Read raw tile data
    uint32 tileIndex = 0; // Assuming tile index 0 for simplicity
    tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, buffer, bufferSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to read raw tile
    }

    // Flush data
    if (TIFFFlushData(tif) != 1) {
        free(buffer);
        FreeTIFF(tif);
        return 0; // Failed to flush data
    }

    // Get seek procedure (not used in this example, but called for coverage)
    TIFFSeekProc seekProc = TIFFGetSeekProc(tif);

    // Free allocated resources
    free(buffer);
    FreeTIFF(tif);

    return 0; // Success
}
