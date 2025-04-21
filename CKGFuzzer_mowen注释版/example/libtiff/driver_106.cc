#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createTIFFFromInput(const uint8_t* data, size_t size) {
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

// Function to allocate memory safely
void* safeMalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to free allocated memory
void safeFree(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    // Create a TIFF object from the fuzz input
    TIFF* tif = createTIFFFromInput(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    int isMSB2LSB = TIFFIsMSB2LSB(tif);
    if (isMSB2LSB < 0) {
        freeTIFF(tif);
        return 0;
    }

    // Allocate memory for the array of long8
    uint64_t* longArray = (uint64_t*)safeMalloc(sizeof(uint64_t) * (size / sizeof(uint64_t)));
    memcpy(longArray, data, size);

    // Swap the byte order of the array
    TIFFSwabArrayOfLong8(longArray, size / sizeof(uint64_t));

    // Flush the data
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        safeFree(longArray);
        freeTIFF(tif);
        return 0;
    }

    // Read raw tile data
    uint32_t tileIndex = 0; // Assuming tile index 0 for simplicity
    void* tileBuffer = safeMalloc(size);
    tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, tileBuffer, size);
    if (readSize == (tmsize_t)(-1)) {
        safeFree(longArray);
        safeFree(tileBuffer);
        freeTIFF(tif);
        return 0;
    }

    // Convert CIE L*a*b* to XYZ
    TIFFCIELabToRGB cielab;
    float X, Y, Z;
    TIFFCIELabToXYZ(&cielab, 128, 0, 0, &X, &Y, &Z);

    // Free allocated resources
    safeFree(longArray);
    safeFree(tileBuffer);
    freeTIFF(tif);

    return 0;
}
