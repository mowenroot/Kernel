#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object from fuzz input data
TIFF* createTIFFFromFuzzInput(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF object in memory
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
    TIFF* tif = nullptr;
    char emsg[1024] = {0};
    uint32 tile = 0;
    tmsize_t tileSize = 0;
    void* tileData = nullptr;

    // Initialize the TIFF object from fuzz input
    tif = createTIFFFromFuzzInput(data, size);
    if (!tif) {
        return 0; // Early exit if TIFF object creation fails
    }

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA format
    int rgbaOk = TIFFRGBAImageOK(tif, emsg);
    if (rgbaOk) {
        // If the image can be converted, proceed with other operations

        // Call TIFFIsUpSampled to check if the image is upsampled
        int isUpSampled = TIFFIsUpSampled(tif);

        // Call TIFFFlushData to ensure data integrity
        int flushStatus = TIFFFlushData(tif);
        if (flushStatus != 1) {
            // Handle error in flushing data
            freeTIFF(tif);
            return 0;
        }

        // Prepare data for TIFFWriteRawTile and TIFFReadRawTile
        tile = 0; // Assuming tile index 0 for simplicity
        tileSize = size / 2; // Use half of the input size for tile data
        tileData = malloc(tileSize);
        if (!tileData) {
            freeTIFF(tif);
            return 0; // Early exit if memory allocation fails
        }

        // Call TIFFWriteRawTile to write raw tile data
        tmsize_t writeStatus = TIFFWriteRawTile(tif, tile, tileData, tileSize);
        if (writeStatus != tileSize) {
            // Handle error in writing raw tile data
            free(tileData);
            freeTIFF(tif);
            return 0;
        }

        // Call TIFFReadRawTile to read raw tile data
        tmsize_t readStatus = TIFFReadRawTile(tif, tile, tileData, tileSize);
        if (readStatus != tileSize) {
            // Handle error in reading raw tile data
            free(tileData);
            freeTIFF(tif);
            return 0;
        }

        // Free allocated memory
        free(tileData);
    } else {
        // Handle error in TIFFRGBAImageOK
        // Log the error message if needed
    }

    // Free the TIFF object
    freeTIFF(tif);

    return 0; // Return 0 to indicate successful execution
}
