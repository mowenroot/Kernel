#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint16_t) * 2 + sizeof(uint32_t) * 2 + sizeof(int32_t) * 2) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Extract necessary data from the fuzz input
    const uint16_t* shortData = reinterpret_cast<const uint16_t*>(data);
    const uint32_t* uintData = reinterpret_cast<const uint32_t*>(data + sizeof(uint16_t) * 2);
    const int32_t* intData = reinterpret_cast<const int32_t*>(data + sizeof(uint16_t) * 2 + sizeof(uint32_t) * 2);

    // Allocate buffers for reading and writing tiles
    uint16_t* readBuffer = static_cast<uint16_t*>(malloc(size));
    uint16_t* writeBuffer = static_cast<uint16_t*>(malloc(size));
    if (!readBuffer || !writeBuffer) {
        free(readBuffer);
        free(writeBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Initialize variables for tile operations
    uint32_t tile = uintData[0] % 10; // Arbitrary tile number
    tmsize_t tileSize = size / 2; // Assume half the size for tile operations

    // Perform TIFFReadEncodedTile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, readBuffer, tileSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        // Handle error
        free(readBuffer);
        free(writeBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Perform TIFFSwabArrayOfShort
    TIFFSwabArrayOfShort(readBuffer, readSize / sizeof(uint16_t));

    // Perform TIFFWriteEncodedTile
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, writeBuffer, tileSize);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        // Handle error
        free(readBuffer);
        free(writeBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Perform TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        // Handle error
        free(readBuffer);
        free(writeBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Perform TIFFYCbCrtoRGB
    uint32_t r, g, b;
    TIFFYCbCrtoRGB(nullptr, shortData[0], intData[0], intData[1], &r, &g, &b);

    // Free allocated resources
    free(readBuffer);
    free(writeBuffer);
    freeTIFF(tif);

    return 0;
}
