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
    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Buffer for error messages
    char emsg[1024];

    // Initialize variables for API calls
    uint32 tile = 0;
    tmsize_t tileSize = 1024; // Example size, should be derived from data
    void* tileData = malloc(tileSize);
    if (!tileData) {
        freeTIFF(tif);
        return 0; // Failed to allocate memory
    }

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA
    int rgbaOk = TIFFRGBAImageOK(tif, emsg);
    if (rgbaOk) {
        // Set a field in the TIFF file
        int setFieldStatus = TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 100);
        if (setFieldStatus != 1) {
            free(tileData);
            freeTIFF(tif);
            return 0; // Failed to set field
        }

        // Write raw tile data to the TIFF file
        tmsize_t writeStatus = TIFFWriteRawTile(tif, tile, tileData, tileSize);
        if (writeStatus == (tmsize_t)(-1)) {
            free(tileData);
            freeTIFF(tif);
            return 0; // Failed to write raw tile
        }

        // Read raw tile data from the TIFF file
        tmsize_t readStatus = TIFFReadRawTile(tif, tile, tileData, tileSize);
        if (readStatus == (tmsize_t)(-1)) {
            free(tileData);
            freeTIFF(tif);
            return 0; // Failed to read raw tile
        }

        // Flush data to ensure consistency
        int flushStatus = TIFFFlushData(tif);
        if (flushStatus != 1) {
            free(tileData);
            freeTIFF(tif);
            return 0; // Failed to flush data
        }
    }

    // Free allocated resources
    free(tileData);
    freeTIFF(tif);

    return 0; // Success
}
