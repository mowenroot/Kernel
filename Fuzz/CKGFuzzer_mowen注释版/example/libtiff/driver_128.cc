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
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
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

// Function to allocate memory for a buffer
void* allocateBuffer(tmsize_t size) {
    void* buf = _TIFFmalloc(size);
    if (!buf) {
        return nullptr;
    }
    return buf;
}

// Function to free allocated memory
void freeBuffer(void* buf) {
    if (buf) {
        _TIFFfree(buf);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Allocate buffers for tile data
    uint64_t* longArray = (uint64_t*)allocateBuffer(sizeof(uint64_t) * 2);
    if (!longArray) {
        freeTIFF(tif);
        return 0;
    }

    // Copy fuzz input data to the buffer
    memcpy(longArray, data, sizeof(uint64_t) * 2);

    // Call TIFFSwabArrayOfLong8 to swap byte order
    TIFFSwabArrayOfLong8(longArray, 2);

    // Call TIFFFlushData to flush data
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        freeBuffer(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteRawTile to write raw tile data
    tmsize_t writeResult = TIFFWriteRawTile(tif, 0, longArray, sizeof(uint64_t) * 2);
    if (writeResult == (tmsize_t)(-1)) {
        freeBuffer(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Allocate buffer for reading raw tile data
    void* readBuffer = allocateBuffer(sizeof(uint64_t) * 2);
    if (!readBuffer) {
        freeBuffer(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFReadRawTile to read raw tile data
    tmsize_t readResult = TIFFReadRawTile(tif, 0, readBuffer, sizeof(uint64_t) * 2);
    if (readResult == (tmsize_t)(-1)) {
        freeBuffer(readBuffer);
        freeBuffer(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Allocate buffer for RGBA image
    uint32_t* raster = (uint32_t*)allocateBuffer(sizeof(uint32_t) * 16); // Assuming 4x4 image for simplicity
    if (!raster) {
        freeBuffer(readBuffer);
        freeBuffer(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFReadRGBAImage to read RGBA image
    int rgbaResult = TIFFReadRGBAImage(tif, 4, 4, raster, 0);
    if (rgbaResult != 1) {
        freeBuffer(raster);
        freeBuffer(readBuffer);
        freeBuffer(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Free all allocated resources
    freeBuffer(raster);
    freeBuffer(readBuffer);
    freeBuffer(longArray);
    freeTIFF(tif);

    return 0;
}
