#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream and std::ostringstream

// Function to convert fuzz input to a TIFF stream in memory
TIFF* createInMemoryTIFF(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("mem", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to create an output TIFF stream in memory
TIFF* createOutputTIFF() {
    // Create a memory-mapped TIFF stream for output
    std::ostringstream s; // Use std::ostringstream for output
    TIFF* tif = TIFFStreamOpen("mem", &s); // Pass the address of the ostringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32_t) * 3) {
        return 0;
    }

    // Create an in-memory TIFF stream from the fuzz input
    TIFF* tif = createInMemoryTIFF(data, size);
    if (!tif) {
        return 0;
    }

    // Create an output TIFF stream
    TIFF* outputTif = createOutputTIFF();
    if (!outputTif) {
        TIFFClose(tif);
        return 0;
    }

    // Extract parameters from the fuzz input
    uint32_t tile = *reinterpret_cast<const uint32_t*>(data);
    uint32_t w = *reinterpret_cast<const uint32_t*>(data + sizeof(uint32_t));
    uint32_t h = *reinterpret_cast<const uint32_t*>(data + 2 * sizeof(uint32_t));

    // Allocate buffers for reading and writing tiles
    tmsize_t tileSize = TIFFTileSize(tif);
    if (tileSize == 0) {
        TIFFClose(tif);
        TIFFClose(outputTif);
        return 0;
    }

    void* readBuffer = malloc(tileSize);
    void* writeBuffer = malloc(tileSize);
    if (!readBuffer || !writeBuffer) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        TIFFClose(outputTif);
        return 0;
    }

    // Read a tile from the input TIFF
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, readBuffer, tileSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        TIFFClose(outputTif);
        return 0;
    }

    // Write the read tile to the output TIFF
    tmsize_t writeSize = TIFFWriteEncodedTile(outputTif, tile, readBuffer, readSize);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        TIFFClose(outputTif);
        return 0;
    }

    // Flush the output TIFF data
    if (TIFFFlushData(outputTif) != 1) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        TIFFClose(outputTif);
        return 0;
    }

    // Create a TIFFRGBAImage structure for reading RGBA data
    TIFFRGBAImage img;
    if (!TIFFRGBAImageBegin(&img, tif, 0, nullptr)) {
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        TIFFClose(outputTif);
        return 0;
    }

    // Allocate buffer for RGBA image data
    uint32_t* raster = (uint32_t*)malloc(w * h * sizeof(uint32_t));
    if (!raster) {
        TIFFRGBAImageEnd(&img);
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        TIFFClose(outputTif);
        return 0;
    }

    // Read RGBA image data
    if (!TIFFRGBAImageGet(&img, raster, w, h)) {
        TIFFRGBAImageEnd(&img);
        free(raster);
        free(readBuffer);
        free(writeBuffer);
        TIFFClose(tif);
        TIFFClose(outputTif);
        return 0;
    }

    // Swap byte order of the RGBA image data
    TIFFSwabArrayOfLong((uint32_t*)raster, w * h);

    // Clean up
    TIFFRGBAImageEnd(&img);
    free(raster);
    free(readBuffer);
    free(writeBuffer);
    TIFFClose(tif);
    TIFFClose(outputTif);

    return 0;
}
