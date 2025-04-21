#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory
TIFF* createTIFFInMemory(const char* data) {
    std::istringstream s(data); // Use std::istringstream instead of tiff::MemStream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        fprintf(stderr, "Failed to create TIFF object in memory\n");
        return nullptr;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* inputStr = fuzzInputToString(data, size);
    if (!inputStr) return 0;

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(inputStr);
    if (!tif) {
        free(inputStr);
        return 0;
    }

    // Initialize variables
    uint32_t tileIndex = 0;
    uint32_t tileWidth = 16; // Example width
    uint32_t tileHeight = 16; // Example height
    uint32_t* raster = (uint32_t*)malloc(tileWidth * tileHeight * sizeof(uint32_t));
    if (!raster) {
        TIFFClose(tif);
        free(inputStr);
        return 0;
    }

    // Set client data
    thandle_t clientData = (thandle_t)tif;
    TIFFSetClientdata(tif, clientData);

    // Write raw tile data
    tmsize_t writeSize = TIFFWriteRawTile(tif, tileIndex, inputStr, size);
    if (writeSize == (tmsize_t)(-1)) {
        fprintf(stderr, "Failed to write raw tile data\n");
    }

    // Read raw tile data
    tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, raster, tileWidth * tileHeight * sizeof(uint32_t));
    if (readSize == (tmsize_t)(-1)) {
        fprintf(stderr, "Failed to read raw tile data\n");
    }

    // Get RGBA image data
    TIFFRGBAImage img;
    if (TIFFRGBAImageBegin(&img, tif, 0, nullptr)) {
        int result = TIFFRGBAImageGet(&img, raster, tileWidth, tileHeight);
        if (result == 0) {
            fprintf(stderr, "Failed to get RGBA image data\n");
        }
        TIFFRGBAImageEnd(&img);
    } else {
        fprintf(stderr, "Failed to begin RGBA image processing\n");
    }

    // Flush data
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        fprintf(stderr, "Failed to flush data\n");
    }

    // Clean up
    TIFFClose(tif);
    free(raster);
    free(inputStr);

    return 0;
}
