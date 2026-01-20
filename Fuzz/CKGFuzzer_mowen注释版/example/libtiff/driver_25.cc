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
    std::string tiffData = FuzzInputToString(data, size);
    std::istringstream s(tiffData); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        // Not enough data to proceed
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = CreateTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Extract necessary data from the fuzz input
    uint32 tile = *reinterpret_cast<const uint32*>(data);
    uint32 arraySize = *reinterpret_cast<const uint32*>(data + 4);

    // Allocate buffers for the operations
    uint64* long8Array = static_cast<uint64*>(malloc(arraySize * sizeof(uint64)));
    uint16* shortArray = static_cast<uint16*>(malloc(arraySize * sizeof(uint16)));
    uint32* longArray = static_cast<uint32*>(malloc(arraySize * sizeof(uint32)));
    void* tileBuffer = malloc(TIFFTileSize(tif));

    if (!long8Array || !shortArray || !longArray || !tileBuffer) {
        TIFFClose(tif);
        free(long8Array);
        free(shortArray);
        free(longArray);
        free(tileBuffer);
        return 0;
    }

    // Initialize arrays with some data (for demonstration purposes)
    memset(long8Array, 0xAA, arraySize * sizeof(uint64));
    memset(shortArray, 0xBB, arraySize * sizeof(uint16));
    memset(longArray, 0xCC, arraySize * sizeof(uint32));

    // Perform the operations
    TIFFSwabArrayOfLong8(long8Array, arraySize);
    TIFFSwabArrayOfShort(shortArray, arraySize);
    TIFFSwabLong(longArray);

    // Read encoded tile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, tileBuffer, TIFFTileSize(tif));
    if (readSize == static_cast<tmsize_t>(-1)) {
        TIFFClose(tif);
        free(long8Array);
        free(shortArray);
        free(longArray);
        free(tileBuffer);
        return 0;
    }

    // Read raw tile
    readSize = TIFFReadRawTile(tif, tile, tileBuffer, TIFFTileSize(tif));
    if (readSize == static_cast<tmsize_t>(-1)) {
        TIFFClose(tif);
        free(long8Array);
        free(shortArray);
        free(longArray);
        free(tileBuffer);
        return 0;
    }

    // Clean up
    TIFFClose(tif);
    free(long8Array);
    free(shortArray);
    free(longArray);
    free(tileBuffer);

    return 0;
}
