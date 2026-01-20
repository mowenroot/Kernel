#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF stream in memory
TIFF* createInMemoryTIFF(const uint8_t* data, size_t size) {
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

// Function to free resources allocated by TIFFRGBAImageBegin
void freeTIFFRGBAImage(TIFFRGBAImage* img) {
    if (img->redcmap) _TIFFfree(img->redcmap);
    if (img->greencmap) _TIFFfree(img->greencmap);
    if (img->bluecmap) _TIFFfree(img->bluecmap);
    TIFFRGBAImageEnd(img);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a TIFF stream in memory from the fuzz input
    TIFF* tif = createInMemoryTIFF(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize variables for API calls
    char emsg[1024] = {0};
    TIFFRGBAImage img;
    memset(&img, 0, sizeof(img));

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA format
    int ok = TIFFRGBAImageOK(tif, emsg);
    if (!ok) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFRGBAImageBegin to initialize the TIFFRGBAImage structure
    int result = TIFFRGBAImageBegin(&img, tif, 0, emsg);
    if (!result) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFFlushData to ensure data integrity by flushing buffered data
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        freeTIFFRGBAImage(&img);
        TIFFClose(tif);
        return 0;
    }

    // Allocate buffer for reading raw tile data
    tmsize_t tileSize = TIFFTileSize(tif);
    if (tileSize <= 0) {
        freeTIFFRGBAImage(&img);
        TIFFClose(tif);
        return 0;
    }
    uint8_t* readBuffer = (uint8_t*)malloc(tileSize);
    if (!readBuffer) {
        freeTIFFRGBAImage(&img);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile to read raw tile data
    uint32 tile = 0; // Assuming tile index 0 for simplicity
    tmsize_t readSize = TIFFReadRawTile(tif, tile, readBuffer, tileSize);
    if (readSize == (tmsize_t)(-1)) {
        free(readBuffer);
        freeTIFFRGBAImage(&img);
        TIFFClose(tif);
        return 0;
    }

    // Allocate buffer for writing raw tile data
    uint8_t* writeBuffer = (uint8_t*)malloc(tileSize);
    if (!writeBuffer) {
        free(readBuffer);
        freeTIFFRGBAImage(&img);
        TIFFClose(tif);
        return 0;
    }

    // Copy read data to write buffer
    memcpy(writeBuffer, readBuffer, readSize);

    // Call TIFFWriteRawTile to write raw tile data
    tmsize_t writeSize = TIFFWriteRawTile(tif, tile, writeBuffer, tileSize);
    if (writeSize != tileSize) {
        free(readBuffer);
        free(writeBuffer);
        freeTIFFRGBAImage(&img);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated resources
    free(readBuffer);
    free(writeBuffer);
    freeTIFFRGBAImage(&img);
    TIFFClose(tif);

    return 0;
}
