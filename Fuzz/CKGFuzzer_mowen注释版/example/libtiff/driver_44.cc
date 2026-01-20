#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
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
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Buffer for raw tile data
    uint8_t* rawTileBuffer = nullptr;
    tmsize_t rawTileBufferSize = 0;

    // Buffer for TIFFSwabArrayOfLong8
    uint64_t* swabBuffer = nullptr;
    tmsize_t swabBufferSize = 0;

    // Error message buffer for TIFFRGBAImageOK
    char emsg[1024] = {0};

    // Variables for API parameters
    uint32 tileIndex = 0;
    tmsize_t readSize = 0;

    // Ensure proper initialization to avoid undefined behavior
    int result = 0;

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA format
    if (TIFFRGBAImageOK(tif, emsg)) {
        // Call TIFFWriteDirectory to write a TIFF directory to the file
        result = TIFFWriteDirectory(tif);
        if (result != 1) {
            // Handle error
            goto cleanup;
        }

        // Call TIFFFlushData to ensure data integrity by flushing buffered data
        result = TIFFFlushData(tif);
        if (result != 1) {
            // Handle error
            goto cleanup;
        }

        // Call TIFFReadRawTile to read raw tile data
        tileIndex = *(uint32_t*)(data + size - sizeof(uint32_t)); // Extract tile index from the end of the input
        readSize = size - sizeof(uint32_t); // Use the remaining size for reading

        rawTileBufferSize = TIFFTileSize(tif);
        if (rawTileBufferSize > 0) {
            rawTileBuffer = (uint8_t*)malloc(rawTileBufferSize);
            if (!rawTileBuffer) {
                // Handle memory allocation failure
                goto cleanup;
            }

            readSize = TIFFReadRawTile(tif, tileIndex, rawTileBuffer, rawTileBufferSize);
            if (readSize == (tmsize_t)(-1)) {
                // Handle error
                goto cleanup;
            }

            // Call TIFFSwabArrayOfLong8 to reverse the byte order of the raw tile data
            swabBufferSize = readSize / sizeof(uint64_t);
            swabBuffer = (uint64_t*)malloc(readSize);
            if (!swabBuffer) {
                // Handle memory allocation failure
                goto cleanup;
            }

            memcpy(swabBuffer, rawTileBuffer, readSize);
            TIFFSwabArrayOfLong8(swabBuffer, swabBufferSize);
        }
    }

cleanup:
    // Free allocated resources
    free(rawTileBuffer);
    free(swabBuffer);
    freeTIFF(tif);

    return 0;
}
