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

// Function to create a TIFF object in memory from the fuzz input
TIFF* CreateTIFFInMemory(const uint8_t* data, size_t size) {
    std::string fuzzInput = FuzzInputToString(data, size);
    std::istringstream s(fuzzInput); // Create an istringstream from the fuzz input
    return TIFFStreamOpen("memory", &s); // Correctly call TIFFStreamOpen with 2 arguments
}

// Function to free the TIFF object and associated memory
void FreeTIFFInMemory(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        // Not enough data to proceed
        return 0;
    }

    TIFF* tif = nullptr;
    void* buffer = nullptr;
    tmsize_t bufferSize = 0;
    uint32 tile = 0;

    // Initialize variables
    tile = static_cast<uint32>(data[0]);
    bufferSize = static_cast<tmsize_t>(data[1]) * 1024; // Arbitrary size, adjust as needed
    buffer = malloc(bufferSize);
    if (!buffer) {
        return 0; // Allocation failed
    }

    // Create TIFF object in memory
    tif = CreateTIFFInMemory(data + 2, size - 2);
    if (!tif) {
        free(buffer);
        return 0; // Failed to create TIFF object
    }

    // Call TIFFGetCloseProc
    TIFFCloseProc closeProc = TIFFGetCloseProc(tif);
    if (closeProc) {
        // This is a function pointer, no need to call it here
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        // Handle error
        FreeTIFFInMemory(tif);
        free(buffer);
        return 0;
    }

    // Call TIFFReadEncodedTile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buffer, bufferSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        // Handle error
        FreeTIFFInMemory(tif);
        free(buffer);
        return 0;
    }

    // Call TIFFWriteRawTile
    tmsize_t writeSize = TIFFWriteRawTile(tif, tile, buffer, readSize);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        // Handle error
        FreeTIFFInMemory(tif);
        free(buffer);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t rawReadSize = TIFFReadRawTile(tif, tile, buffer, bufferSize);
    if (rawReadSize == static_cast<tmsize_t>(-1)) {
        // Handle error
        FreeTIFFInMemory(tif);
        free(buffer);
        return 0;
    }

    // Clean up
    FreeTIFFInMemory(tif);
    free(buffer);

    return 0;
}
