#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const std::string& input) {
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(input);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Variables for API parameters
    uint32 strip = 0;
    uint32 tile = 0;
    uint16 dirn = 0;
    toff_t diroff = 0;
    const TIFFFieldArray* infoarray = nullptr;
    void* buf = nullptr;
    tmsize_t bufSize = 0;

    // Ensure proper initialization of variables
    strip = static_cast<uint32>(data[0]);
    tile = static_cast<uint32>(data[1]);
    dirn = static_cast<uint16>(data[2]);
    diroff = static_cast<toff_t>(data[3]);
    bufSize = static_cast<tmsize_t>(data[4]);

    // Allocate buffer for reading strips and tiles
    buf = malloc(bufSize);
    if (!buf) {
        TIFFClose(tif);
        return 0; // Failed to allocate buffer
    }

    // Call TIFFReadEncodedStrip
    tmsize_t stripSize = TIFFReadEncodedStrip(tif, strip, buf, bufSize);
    if (stripSize == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    // Call TIFFReadRawTile
    tmsize_t tileSize = TIFFReadRawTile(tif, tile, buf, bufSize);
    if (tileSize == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    // Call TIFFUnlinkDirectory
    int unlinkResult = TIFFUnlinkDirectory(tif, dirn);
    if (!unlinkResult) {
        // Handle error
    }

    // Call TIFFReadCustomDirectory
    int readCustomDirResult = TIFFReadCustomDirectory(tif, diroff, infoarray);
    if (!readCustomDirResult) {
        // Handle error
    }

    // Call TIFFSetField
    int setFieldResult = TIFFSetField(tif, TIFFTAG_IMAGEWIDTH, static_cast<uint32>(data[5]));
    if (!setFieldResult) {
        // Handle error
    }

    // Free allocated resources
    free(buf);
    TIFFClose(tif);

    return 0; // Return 0 to indicate success
}
