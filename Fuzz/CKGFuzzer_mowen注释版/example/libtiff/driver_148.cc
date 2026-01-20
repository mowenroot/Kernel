#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object from fuzz input
TIFF* createTIFFFromFuzzInput(const uint8_t* data, size_t size) {
    char* name = fuzzInputToString(data, size);
    if (!name) return nullptr;
    TIFF* tif = TIFFFdOpen(0, name, "rm"); // 'r' for read, 'm' for memory-mapped
    free(name);
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0; // Ensure there's enough data

    // Create TIFF object from fuzz input
    TIFF* tif = createTIFFFromFuzzInput(data, size);
    if (!tif) return 0;

    // Allocate buffers for tile data
    tmsize_t tileSize = TIFFTileSize(tif);
    if (tileSize == 0) {
        TIFFClose(tif);
        return 0;
    }
    uint64_t* tileBuffer = (uint64_t*)malloc(tileSize);
    if (!tileBuffer) {
        TIFFClose(tif);
        return 0;
    }

    // Read raw tile data
    uint32 tile = 0; // Assuming tile index 0 for simplicity
    tmsize_t readSize = TIFFReadRawTile(tif, tile, tileBuffer, tileSize);
    if (readSize == (tmsize_t)(-1)) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Swap byte order of the tile data
    TIFFSwabArrayOfLong8(tileBuffer, readSize / sizeof(uint64_t));

    // Read encoded tile data
    uint8_t* encodedBuffer = (uint8_t*)malloc(tileSize);
    if (!encodedBuffer) {
        free(tileBuffer);
        TIFFClose(tif);
        return 0;
    }
    tmsize_t encodedSize = TIFFReadEncodedTile(tif, tile, encodedBuffer, tileSize);
    if (encodedSize == (tmsize_t)(-1)) {
        free(tileBuffer);
        free(encodedBuffer);
        TIFFClose(tif);
        return 0;
    }

    // Get bit reversal table
    const unsigned char* bitRevTable = TIFFGetBitRevTable(1); // Assuming reversed bit order

    // Clean up
    free(tileBuffer);
    free(encodedBuffer);
    TIFFClose(tif);

    return 0;
}
