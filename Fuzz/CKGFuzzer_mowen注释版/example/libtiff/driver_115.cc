#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFFRGBAImage object
TIFFRGBAImage* CreateTIFFRGBAImage() {
    TIFFRGBAImage* img = static_cast<TIFFRGBAImage*>(_TIFFmalloc(sizeof(TIFFRGBAImage)));
    if (!img) {
        return nullptr;
    }
    memset(img, 0, sizeof(TIFFRGBAImage));
    return img;
}

// Function to create a TIFF object
TIFF* CreateTIFF(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free a TIFFRGBAImage object
void FreeTIFFRGBAImage(TIFFRGBAImage* img) {
    if (img) {
        TIFFRGBAImageEnd(img);
        _TIFFfree(img);
    }
}

// Function to free a TIFF object
void FreeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create TIFF and TIFFRGBAImage objects
    TIFF* tif = CreateTIFF(fuzzInput);
    if (!tif) {
        return 0;
    }

    TIFFRGBAImage* img = CreateTIFFRGBAImage();
    if (!img) {
        FreeTIFF(tif);
        return 0;
    }

    // Initialize variables
    uint64_t tileIndex = 0;
    uint64_t* tileData = static_cast<uint64_t*>(_TIFFmalloc(sizeof(uint64_t) * 8));
    if (!tileData) {
        FreeTIFFRGBAImage(img);
        FreeTIFF(tif);
        return 0;
    }

    // Perform operations using the provided APIs
    TIFFSwabArrayOfLong8(tileData, 8);

    if (TIFFFlushData(tif) != 1) {
        _TIFFfree(tileData);
        FreeTIFFRGBAImage(img);
        FreeTIFF(tif);
        return 0;
    }

    if (TIFFWriteRawTile(tif, tileIndex, tileData, sizeof(uint64_t) * 8) == static_cast<tmsize_t>(-1)) {
        _TIFFfree(tileData);
        FreeTIFFRGBAImage(img);
        FreeTIFF(tif);
        return 0;
    }

    if (TIFFReadRawTile(tif, tileIndex, tileData, sizeof(uint64_t) * 8) == static_cast<tmsize_t>(-1)) {
        _TIFFfree(tileData);
        FreeTIFFRGBAImage(img);
        FreeTIFF(tif);
        return 0;
    }

    // Clean up
    _TIFFfree(tileData);
    FreeTIFFRGBAImage(img);
    FreeTIFF(tif);

    return 0;
}
