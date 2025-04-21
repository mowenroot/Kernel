#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return NULL;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const char* str) {
    // Use std::istringstream to create a stream from the string
    std::istringstream s(str);
    // Open a TIFF stream in memory using the stream
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        TIFFErrorExt(0, "createTIFFInMemory", "Failed to create TIFF object in memory");
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* tiffData = fuzzInputToString(data, size);
    if (!tiffData) return 0;

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(tiffData);
    if (!tif) {
        free(tiffData);
        return 0;
    }

    // Initialize variables
    TIFFRGBAImage img;
    uint32_t* raster = NULL;
    uint32_t w = 1024, h = 1024; // Default dimensions
    TIFFCodec* codecs = NULL;
    uint16_t dirn = 1; // Default directory number
    uint32_t tile = 0; // Default tile number
    void* buf = NULL;
    tmsize_t bufSize = 1024 * 1024; // 1MB buffer

    // Allocate buffer for raw tile data
    buf = malloc(bufSize);
    if (!buf) {
        TIFFClose(tif);
        free(tiffData);
        return 0;
    }

    // Call TIFFGetConfiguredCODECs
    codecs = TIFFGetConfiguredCODECs();
    if (codecs) {
        _TIFFfree(codecs);
    }

    // Call TIFFUnlinkDirectory
    if (TIFFUnlinkDirectory(tif, dirn) != 1) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFUnlinkDirectory failed");
    }

    // Call TIFFReadRawTile
    if (TIFFReadRawTile(tif, tile, buf, bufSize) == (tmsize_t)(-1)) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFReadRawTile failed");
    }

    // Call TIFFRGBAImageGet
    if (TIFFRGBAImageBegin(&img, tif, 0, NULL) == 1) {
        raster = (uint32_t*)malloc(w * h * sizeof(uint32_t));
        if (raster) {
            if (TIFFRGBAImageGet(&img, raster, w, h) != 1) {
                TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFRGBAImageGet failed");
            }
            free(raster);
        }
        TIFFRGBAImageEnd(&img);
    } else {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFRGBAImageBegin failed");
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFFlushData failed");
    }

    // Clean up
    TIFFClose(tif);
    free(tiffData);
    free(buf);

    return 0;
}
