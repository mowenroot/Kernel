#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include sstream for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createTIFFFromFuzzInput(const uint8_t* data, size_t size) {
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

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    TIFFRGBAImage img;
    char emsg[1024];
    uint32* raster = nullptr;
    tmsize_t tileSize = 0;
    uint32 tileIndex = 0;
    uint32 w = 0, h = 0;
    void* tileBuffer = nullptr;

    // Initialize TIFF object from fuzz input
    tif = createTIFFFromFuzzInput(data, size);
    if (!tif) {
        return 0;
    }

    // Check if the TIFF image can be converted to RGBA format
    if (!TIFFRGBAImageOK(tif, emsg)) {
        TIFFClose(tif);
        return 0;
    }

    // Begin RGBA image processing
    if (!TIFFRGBAImageBegin(&img, tif, 0, emsg)) {
        TIFFClose(tif);
        return 0;
    }

    // Calculate tile size
    tileSize = TIFFTileSize(tif);
    if (tileSize <= 0) {
        TIFFRGBAImageEnd(&img);
        TIFFClose(tif);
        return 0;
    }

    // Allocate buffer for raw tile data
    tileBuffer = _TIFFmalloc(tileSize);
    if (!tileBuffer) {
        TIFFRGBAImageEnd(&img);
        TIFFClose(tif);
        return 0;
    }

    // Read raw tile data
    if (TIFFReadRawTile(tif, tileIndex, tileBuffer, tileSize) == (tmsize_t)(-1)) {
        _TIFFfree(tileBuffer);
        TIFFRGBAImageEnd(&img);
        TIFFClose(tif);
        return 0;
    }

    // Allocate raster buffer for RGBA image
    w = img.width;
    h = img.height;
    raster = (uint32*) _TIFFmalloc(w * h * sizeof(uint32));
    if (!raster) {
        _TIFFfree(tileBuffer);
        TIFFRGBAImageEnd(&img);
        TIFFClose(tif);
        return 0;
    }

    // Get RGBA image data
    if (!TIFFRGBAImageGet(&img, raster, w, h)) {
        _TIFFfree(raster);
        _TIFFfree(tileBuffer);
        TIFFRGBAImageEnd(&img);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    _TIFFfree(raster);
    _TIFFfree(tileBuffer);
    TIFFRGBAImageEnd(&img);
    TIFFClose(tif);

    return 0;
}
