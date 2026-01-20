#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory from the fuzz input
TIFF* createTIFFFromFuzzInput(const uint8_t* data, size_t size) {
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a TIFF object from the fuzz input
    TIFF* tif = createTIFFFromFuzzInput(data, size);
    if (tif == NULL) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    uint32_t rwidth = 1024;
    uint32_t rheight = 1024;
    uint32_t* raster = (uint32_t*)malloc(rwidth * rheight * sizeof(uint32_t));
    if (raster == NULL) {
        TIFFClose(tif);
        return 0;
    }

    // Derive API inputs from fuzz input
    uint16_t scheme = (uint16_t)(data[0] % 256);
    int orientation = (int)(data[1] % 8);
    tmsize_t cc = (tmsize_t)(data[2] % 1024);
    void* buf = malloc(cc);
    if (buf == NULL) {
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFIsCODECConfigured
    int codecConfigured = TIFFIsCODECConfigured(scheme);
    if (codecConfigured) {
        // Call TIFFWriteRawTile
        tmsize_t writeResult = TIFFWriteRawTile(tif, tile, buf, cc);
        if (writeResult == (tmsize_t)(-1)) {
            free(buf);
            free(raster);
            TIFFClose(tif);
            return 0;
        }

        // Call TIFFFlushData
        int flushResult = TIFFFlushData(tif);
        if (flushResult == 0) {
            free(buf);
            free(raster);
            TIFFClose(tif);
            return 0;
        }

        // Call TIFFReadRawTile
        tmsize_t readResult = TIFFReadRawTile(tif, tile, buf, cc);
        if (readResult == (tmsize_t)(-1)) {
            free(buf);
            free(raster);
            TIFFClose(tif);
            return 0;
        }
    }

    // Call TIFFReadRGBAImageOriented
    int readRGBAImageResult = TIFFReadRGBAImageOriented(tif, rwidth, rheight, raster, orientation, 0);
    if (readRGBAImageResult == 0) {
        free(buf);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Free allocated resources
    free(buf);
    free(raster);
    TIFFClose(tif);

    return 0;
}
