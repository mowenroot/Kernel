#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream>

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const std::string& str) {
    TIFF* tif = TIFFStreamOpen("MemTIFF", new std::istringstream(str));
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(fuzzInput);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32 rwidth = 1024;
    uint32 rheight = 1024;
    uint32* raster = static_cast<uint32*>(_TIFFmalloc(rwidth * rheight * sizeof(uint32)));
    if (!raster) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRGBAImageOriented
    int orientation = 1;
    int stop = 0;
    int ok = TIFFReadRGBAImageOriented(tif, rwidth, rheight, raster, orientation, stop);
    if (!ok) {
        _TIFFfree(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFSwabArrayOfLong8
    uint64* longArray = static_cast<uint64*>(_TIFFmalloc(rwidth * sizeof(uint64)));
    if (!longArray) {
        _TIFFfree(raster);
        TIFFClose(tif);
        return 0;
    }
    TIFFSwabArrayOfLong8(longArray, rwidth);
    _TIFFfree(longArray);

    // Call TIFFSetClientInfo
    void* clientData = nullptr;
    const char* clientName = "FuzzClient";
    TIFFSetClientInfo(tif, clientData, clientName);

    // Call TIFFUnlinkDirectory
    uint16 dirn = 1;
    int unlinkOk = TIFFUnlinkDirectory(tif, dirn);
    if (!unlinkOk) {
        _TIFFfree(raster);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    uint32 tile = 0;
    void* tileBuf = _TIFFmalloc(rwidth * sizeof(uint32));
    if (!tileBuf) {
        _TIFFfree(raster);
        TIFFClose(tif);
        return 0;
    }
    tmsize_t tileSize = TIFFReadRawTile(tif, tile, tileBuf, rwidth * sizeof(uint32));
    if (tileSize == static_cast<tmsize_t>(-1)) {
        _TIFFfree(raster);
        _TIFFfree(tileBuf);
        TIFFClose(tif);
        return 0;
    }
    _TIFFfree(tileBuf);

    // Free allocated resources
    _TIFFfree(raster);
    TIFFClose(tif);

    return 0;
}
