#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF stream from fuzz input data
TIFF* createTIFFStream(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        fprintf(stderr, "Failed to create TIFF stream from fuzz input data.\n");
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
    uint64_t* longArray = nullptr;
    void* tileBuffer = nullptr;
    tmsize_t tileBufferSize = 0;
    uint32 tileIndex = 0;
    int fileDescriptor = 0;
    FILE* outputFile = nullptr;

    // Ensure the input data is large enough to be meaningful
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Create a TIFF stream from the fuzz input data
    tif = createTIFFStream(data, size);
    if (!tif) {
        return 0;
    }

    // Allocate memory for the long array
    longArray = (uint64_t*)malloc(size);
    if (!longArray) {
        freeTIFFStream(tif);
        return 0;
    }

    // Copy the fuzz input data to the long array
    memcpy(longArray, data, size);

    // Call TIFFSwabArrayOfLong8 to reverse the byte order of the long array
    TIFFSwabArrayOfLong8(longArray, size / sizeof(uint64_t));

    // Allocate memory for the tile buffer
    tileBufferSize = TIFFTileSize(tif);
    if (tileBufferSize <= 0) {
        free(longArray);
        freeTIFFStream(tif);
        return 0;
    }
    tileBuffer = malloc(tileBufferSize);
    if (!tileBuffer) {
        free(longArray);
        freeTIFFStream(tif);
        return 0;
    }

    // Call TIFFReadEncodedTile to read and decode a tile
    tileIndex = *(uint32*)data; // Use the first 4 bytes as the tile index
    if (TIFFReadEncodedTile(tif, tileIndex, tileBuffer, tileBufferSize) == (tmsize_t)(-1)) {
        fprintf(stderr, "TIFFReadEncodedTile failed.\n");
    }

    // Call TIFFSetFileno to set the file descriptor
    fileDescriptor = *(int*)(data + sizeof(uint32)); // Use the next 4 bytes as the file descriptor
    TIFFSetFileno(tif, fileDescriptor);

    // Call TIFFReadRawTile to read raw tile data
    if (TIFFReadRawTile(tif, tileIndex, tileBuffer, tileBufferSize) == (tmsize_t)(-1)) {
        fprintf(stderr, "TIFFReadRawTile failed.\n");
    }

    // Open a temporary file for output
    outputFile = fopen("output_file", "w");
    if (!outputFile) {
        free(longArray);
        free(tileBuffer);
        freeTIFFStream(tif);
        return 0;
    }

    // Call TIFFPrintDirectory to print directory information to the file
    TIFFPrintDirectory(tif, outputFile, 0);

    // Close the output file
    fclose(outputFile);

    // Free allocated resources
    free(longArray);
    free(tileBuffer);
    freeTIFFStream(tif);

    return 0;
}
