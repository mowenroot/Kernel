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

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    uint64_t* longArray = nullptr;
    uint32 tile = 0;
    void* buf = nullptr;
    tmsize_t bufSize = 0;
    int result = 0;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    // Create a TIFF object from the fuzz input
    tif = createTIFFFromFuzzInput(data, size);
    if (!tif) {
        return 0;
    }

    // Allocate memory for the long array and buffer
    longArray = (uint64_t*)malloc(sizeof(uint64_t) * 2);
    if (!longArray) {
        freeTIFF(tif);
        return 0;
    }

    bufSize = size / 2;
    buf = malloc(bufSize);
    if (!buf) {
        free(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Initialize the long array with fuzz input data
    memcpy(longArray, data, sizeof(uint64_t) * 2);

    // Call TIFFSwabArrayOfLong8
    TIFFSwabArrayOfLong8(longArray, 2);

    // Call TIFFReadEncodedTile
    tile = (uint32)(longArray[0] % 10); // Assuming a reasonable tile number
    result = TIFFReadEncodedTile(tif, tile, buf, bufSize);
    if (result == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFReadRawTile
    result = TIFFReadRawTile(tif, tile, buf, bufSize);
    if (result == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFSetSubDirectory
    uint64_t subDirOffset = longArray[1];
    result = TIFFSetSubDirectory(tif, subDirOffset);
    if (!result) {
        // Handle error
    }

    // Call TIFFReadDirectory
    result = TIFFReadDirectory(tif);
    if (!result) {
        // Handle error
    }

    // Free allocated resources
    free(longArray);
    free(buf);
    freeTIFF(tif);

    return 0;
}
