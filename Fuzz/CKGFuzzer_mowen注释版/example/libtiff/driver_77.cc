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

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const std::string& data) {
    // Create a TIFF object in memory
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated resources
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string tiffData = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(tiffData);
    if (!tif) {
        return 0;
    }

    // Variables for API calls
    uint32 tile = 0;
    void* buf = nullptr;
    tmsize_t bufSize = 0;
    uint32 fieldTag = 0;

    // Allocate buffer for reading/writing tiles
    bufSize = TIFFTileSize(tif);
    if (bufSize > 0) {
        buf = malloc(bufSize);
        if (!buf) {
            freeTIFF(tif);
            return 0;
        }
    }

    // Call TIFFFieldTag to get a field tag
    const TIFFField* field = TIFFFindField(tif, TIFFTAG_IMAGEWIDTH, TIFF_ANY);
    if (field) {
        fieldTag = TIFFFieldTag(field);
    }

    // Call TIFFReadEncodedTile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buf, bufSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    // Call TIFFWriteEncodedTile
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, buf, bufSize);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    // Call TIFFFlushData
    int flushResult = TIFFFlushData(tif);
    if (flushResult != 1) {
        // Handle error
    }

    // Call TIFFRewriteDirectory
    int rewriteResult = TIFFRewriteDirectory(tif);
    if (rewriteResult != 1) {
        // Handle error
    }

    // Free allocated resources
    if (buf) {
        free(buf);
    }
    freeTIFF(tif);

    return 0;
}
