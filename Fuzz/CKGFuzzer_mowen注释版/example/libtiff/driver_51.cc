#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated memory
void freeTIFFInMemory(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Allocate buffers for API calls
    uint64_t* long8Array = static_cast<uint64_t*>(malloc(size));
    uint8_t* byteArray = static_cast<uint8_t*>(malloc(size));
    void* tileBuffer = malloc(size);

    if (!long8Array || !byteArray || !tileBuffer) {
        free(long8Array);
        free(byteArray);
        free(tileBuffer);
        freeTIFFInMemory(tif);
        return 0; // Memory allocation failed
    }

    // Initialize buffers with fuzz input data
    memcpy(long8Array, data, size);
    memcpy(byteArray, data, size);
    memcpy(tileBuffer, data, size);

    // Call TIFFSwabArrayOfLong8
    TIFFSwabArrayOfLong8(long8Array, size / sizeof(uint64_t));

    // Call TIFFReverseBits
    TIFFReverseBits(byteArray, size);

    // Call TIFFWriteTile
    uint32_t x = 0, y = 0, z = 0;
    uint16_t s = 0;
    tmsize_t writeResult = TIFFWriteTile(tif, tileBuffer, x, y, z, s);
    if (writeResult == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    // Call TIFFReadRawTile
    uint32_t tile = 0;
    tmsize_t readResult = TIFFReadRawTile(tif, tile, tileBuffer, size);
    if (readResult == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    // Call TIFFReadCustomDirectory
    toff_t diroff = 0;
    const TIFFFieldArray* infoarray = nullptr;
    int readCustomDirResult = TIFFReadCustomDirectory(tif, diroff, infoarray);
    if (readCustomDirResult == 0) {
        // Handle error
    }

    // Free allocated resources
    free(long8Array);
    free(byteArray);
    free(tileBuffer);
    freeTIFFInMemory(tif);

    return 0; // Return 0 to indicate success
}
