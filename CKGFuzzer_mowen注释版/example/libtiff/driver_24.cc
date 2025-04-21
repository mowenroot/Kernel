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
    // Create a TIFF object in memory
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzData = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzData);
    if (!tif) {
        return 0;
    }

    // Allocate buffers for API calls
    uint64_t* longArray = nullptr;
    double* doubleValue = nullptr;
    void* rawTileBuffer = nullptr;
    tmsize_t rawTileBufferSize = 0;

    // Ensure proper initialization of variables
    uint32_t tileIndex = 0;
    tmsize_t arraySize = 0;

    // Derive inputs from fuzz data
    if (size >= sizeof(uint32_t) + sizeof(tmsize_t) + sizeof(double)) {
        tileIndex = *reinterpret_cast<const uint32_t*>(data);
        arraySize = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32_t));
        doubleValue = reinterpret_cast<double*>(const_cast<uint8_t*>(data + sizeof(uint32_t) + sizeof(tmsize_t)));
    }

    // Allocate memory for the long array
    if (arraySize > 0) {
        longArray = static_cast<uint64_t*>(malloc(arraySize * sizeof(uint64_t)));
        if (!longArray) {
            TIFFClose(tif);
            return 0;
        }
        memset(longArray, 0, arraySize * sizeof(uint64_t));
    }

    // Allocate memory for the raw tile buffer
    if (size >= sizeof(uint32_t) + sizeof(tmsize_t) + sizeof(double) + sizeof(tmsize_t)) {
        rawTileBufferSize = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32_t) + sizeof(tmsize_t) + sizeof(double));
        if (rawTileBufferSize > 0) {
            rawTileBuffer = malloc(rawTileBufferSize);
            if (!rawTileBuffer) {
                free(longArray);
                TIFFClose(tif);
                return 0;
            }
            memset(rawTileBuffer, 0, rawTileBufferSize);
        }
    }

    // Call TIFFSwabArrayOfLong8
    if (longArray) {
        TIFFSwabArrayOfLong8(longArray, arraySize);
    }

    // Call TIFFSwabDouble
    if (doubleValue) {
        TIFFSwabDouble(doubleValue);
    }

    // Call TIFFReadRawTile
    if (rawTileBuffer && rawTileBufferSize > 0) {
        tmsize_t bytesRead = TIFFReadRawTile(tif, tileIndex, rawTileBuffer, rawTileBufferSize);
        if (bytesRead == static_cast<tmsize_t>(-1)) {
            // Handle error
        }
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        // Handle error
    }

    // Call TIFFRewriteDirectory
    if (TIFFRewriteDirectory(tif) != 1) {
        // Handle error
    }

    // Free allocated resources
    free(longArray);
    free(rawTileBuffer);
    TIFFClose(tif);

    return 0;
}
