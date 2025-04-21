#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
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
    // Convert fuzz input to a string
    std::string fuzzInput = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint64_t* longArray = nullptr;
    tmsize_t longArraySize = 0;
    uint32_t tileIndex = 0;
    void* tileData = nullptr;
    tmsize_t tileDataSize = 0;
    TIFFCIELabToRGB cielab;
    float X = 0.0f, Y = 0.0f, Z = 0.0f;
    uint32_t r = 0, g = 0, b = 0;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size >= sizeof(uint64_t) * 2) {
        longArraySize = size / sizeof(uint64_t);
        longArray = static_cast<uint64_t*>(malloc(size));
        if (longArray) {
            memcpy(longArray, data, size);
            TIFFSwabArrayOfLong8(longArray, longArraySize);
        }
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        // Handle error
    }

    // Call TIFFWriteRawTile
    if (size >= sizeof(uint32_t)) {
        tileIndex = *reinterpret_cast<const uint32_t*>(data);
        tileDataSize = size - sizeof(uint32_t);
        tileData = malloc(tileDataSize);
        if (tileData) {
            memcpy(tileData, data + sizeof(uint32_t), tileDataSize);
            tmsize_t writeResult = TIFFWriteRawTile(tif, tileIndex, tileData, tileDataSize);
            if (writeResult == static_cast<tmsize_t>(-1)) {
                // Handle error
            }
        }
    }

    // Call TIFFXYZToRGB
    if (size >= sizeof(float) * 3) {
        X = *reinterpret_cast<const float*>(data);
        Y = *reinterpret_cast<const float*>(data + sizeof(float));
        Z = *reinterpret_cast<const float*>(data + 2 * sizeof(float));
        TIFFXYZToRGB(&cielab, X, Y, Z, &r, &g, &b);
    }

    // Call TIFFReadRawTile
    if (size >= sizeof(uint32_t)) {
        tileIndex = *reinterpret_cast<const uint32_t*>(data);
        tileDataSize = size - sizeof(uint32_t);
        tileData = malloc(tileDataSize);
        if (tileData) {
            tmsize_t readResult = TIFFReadRawTile(tif, tileIndex, tileData, tileDataSize);
            if (readResult == static_cast<tmsize_t>(-1)) {
                // Handle error
            }
        }
    }

    // Free allocated memory
    free(longArray);
    free(tileData);

    // Free the TIFF object
    freeTIFF(tif);

    return 0;
}
