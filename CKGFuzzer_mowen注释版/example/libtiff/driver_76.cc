#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sstream> // Include for std::istringstream

// Function to handle memory allocation failure
void handleMemoryAllocationFailure() {
    fprintf(stderr, "Memory allocation failed\n");
    exit(1);
}

// Function to handle TIFF errors
void handleTiffError(const char* module, const char* fmt, va_list ap) {
    fprintf(stderr, "TIFF Error in %s: ", module);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

// Function to handle TIFF warnings
void handleTiffWarning(const char* module, const char* fmt, va_list ap) {
    fprintf(stderr, "TIFF Warning in %s: ", module);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFFSetErrorHandler(handleTiffError);
    TIFFSetWarningHandler(handleTiffWarning);

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32_t) * 3) {
        return 0;
    }

    // Convert fuzz input to a string
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    uint32_t l = 0;
    int32_t a = 0;
    int32_t b = 0;
    float X, Y, Z;
    void* buf = nullptr;
    tmsize_t bufSize = 0;

    // Extract values from the fuzz input
    tile = *((uint32_t*)data);
    l = *((uint32_t*)(data + sizeof(uint32_t)));
    a = *((int32_t*)(data + 2 * sizeof(uint32_t)));
    b = *((int32_t*)(data + 2 * sizeof(uint32_t) + sizeof(int32_t)));

    // Call TIFFReadDirectory to read and process TIFF directory entries
    if (TIFFReadDirectory(tif) == 0) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile to read raw tile data
    bufSize = TIFFTileSize(tif);
    if (bufSize > 0) {
        buf = malloc(bufSize);
        if (!buf) {
            handleMemoryAllocationFailure();
        }
        if (TIFFReadRawTile(tif, tile, buf, bufSize) == -1) {
            free(buf);
            TIFFClose(tif);
            return 0;
        }
        free(buf);
    }

    // Call TIFFCIELabToXYZ to convert CIE L*a*b* to XYZ
    TIFFCIELabToXYZ(nullptr, l, a, b, &X, &Y, &Z);

    // Call TIFFSetField to set a TIFF tag
    if (!TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, 1024)) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteEncodedTile to write encoded tile data
    bufSize = TIFFTileSize(tif);
    if (bufSize > 0) {
        buf = malloc(bufSize);
        if (!buf) {
            handleMemoryAllocationFailure();
        }
        if (TIFFWriteEncodedTile(tif, tile, buf, bufSize) == -1) {
            free(buf);
            TIFFClose(tif);
            return 0;
        }
        free(buf);
    }

    // Close the TIFF object
    TIFFClose(tif);

    return 0;
}
