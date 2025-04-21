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
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (tif == NULL) {
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    uint32 w = 1024;
    uint32 h = 1024;
    uint32* raster = (uint32*)malloc(w * h * sizeof(uint32));
    if (raster == NULL) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFSetClientInfo
    void* clientData = (void*)data;
    TIFFSetClientInfo(tif, clientData, "FuzzClientInfo");

    // Call TIFFReadEncodedTile
    void* buf = malloc(size);
    if (buf == NULL) {
        free(raster);
        TIFFClose(tif);
        return 0;
    }
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buf, size);
    if (readSize == (tmsize_t)(-1)) {
        free(buf);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t rawSize = TIFFReadRawTile(tif, tile, buf, size);
    if (rawSize == (tmsize_t)(-1)) {
        free(buf);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFRGBAImageGet
    TIFFRGBAImage img;
    if (TIFFRGBAImageBegin(&img, tif, 0, NULL)) {
        if (TIFFRGBAImageGet(&img, raster, w, h)) {
            TIFFRGBAImageEnd(&img);
        } else {
            TIFFRGBAImageEnd(&img);
            free(buf);
            free(raster);
            TIFFClose(tif);
            return 0;
        }
    } else {
        free(buf);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        free(buf);
        free(raster);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    free(buf);
    free(raster);
    TIFFClose(tif);
    return 0;
}
