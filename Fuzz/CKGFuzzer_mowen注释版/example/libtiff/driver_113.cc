// fuzz_driver.cpp

#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF stream in memory from the fuzz input
TIFF* createTIFFStream(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        fprintf(stderr, "Failed to create TIFF stream\n");
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF stream
void freeTIFFStream(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    uint32 tile = 0;
    void* buffer = nullptr;
    tmsize_t bufferSize = 0;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32)) {
        return 0;
    }

    // Create a TIFF stream from the fuzz input
    tif = createTIFFStream(data, size);
    if (!tif) {
        return 0;
    }

    // Extract the tile number from the fuzz input
    tile = *((uint32*)data);
    data += sizeof(uint32);
    size -= sizeof(uint32);

    // Allocate a buffer for reading/writing tiles
    bufferSize = TIFFTileSize(tif);
    if (bufferSize == 0) {
        freeTIFFStream(tif);
        return 0;
    }
    buffer = malloc(bufferSize);
    if (!buffer) {
        freeTIFFStream(tif);
        return 0;
    }

    // Call TIFFReadEncodedTile to read the tile data
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buffer, bufferSize);
    if (readSize == (tmsize_t)(-1)) {
        free(buffer);
        freeTIFFStream(tif);
        return 0;
    }

    // Modify the buffer data (for example, set all bytes to 0xAA)
    memset(buffer, 0xAA, bufferSize);

    // Call TIFFWriteEncodedTile to write the modified tile data
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, buffer, bufferSize);
    if (writeSize == (tmsize_t)(-1)) {
        free(buffer);
        freeTIFFStream(tif);
        return 0;
    }

    // Call TIFFCheckpointDirectory to ensure the directory is written
    if (TIFFCheckpointDirectory(tif) != 1) {
        free(buffer);
        freeTIFFStream(tif);
        return 0;
    }

    // Call TIFFFlush to ensure all data is written to the stream
    if (TIFFFlush(tif) != 1) {
        free(buffer);
        freeTIFFStream(tif);
        return 0;
    }

    // Call TIFFPrintDirectory to print the directory information
    TIFFPrintDirectory(tif, stdout, 0);

    // Free the buffer and close the TIFF stream
    free(buffer);
    freeTIFFStream(tif);

    return 0;
}
