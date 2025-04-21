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
    TIFF* tif = TIFFStreamOpen("mem", &s);
    if (!tif) {
        TIFFError("CreateTIFFInMemory", "Failed to create TIFF object in memory");
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
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0; // Early exit if TIFF creation fails
    }

    // Variables for API calls
    uint32 tile = 0; // Assuming tile index 0 for simplicity
    void* buffer = nullptr;
    tmsize_t bufferSize = 0;

    // Allocate buffer for reading/writing tiles
    bufferSize = TIFFTileSize(tif);
    if (bufferSize <= 0) {
        FreeTIFF(tif);
        return 0; // Early exit if buffer size is invalid
    }
    buffer = malloc(bufferSize);
    if (!buffer) {
        FreeTIFF(tif);
        return 0; // Early exit if buffer allocation fails
    }

    // Call TIFFWriteEncodedTile
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, buffer, bufferSize);
    if (writeSize == (tmsize_t)(-1)) {
        TIFFWarning("LLVMFuzzerTestOneInput", "TIFFWriteEncodedTile failed");
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        TIFFWarning("LLVMFuzzerTestOneInput", "TIFFFlushData failed");
    }

    // Call TIFFReadEncodedTile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buffer, bufferSize);
    if (readSize == (tmsize_t)(-1)) {
        TIFFWarning("LLVMFuzzerTestOneInput", "TIFFReadEncodedTile failed");
    }

    // Call TIFFReadRawTile
    tmsize_t rawReadSize = TIFFReadRawTile(tif, tile, buffer, bufferSize);
    if (rawReadSize == (tmsize_t)(-1)) {
        TIFFWarning("LLVMFuzzerTestOneInput", "TIFFReadRawTile failed");
    }

    // Free allocated resources
    free(buffer);
    FreeTIFF(tif);

    return 0; // Return 0 to indicate success
}
