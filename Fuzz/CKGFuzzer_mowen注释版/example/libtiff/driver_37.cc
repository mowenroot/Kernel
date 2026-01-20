#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF object in memory
    TIFF* tif = TIFFStreamOpen("mem", &s); // Pass the address of the istringstream
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

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    char emsg[1024];
    void* buf = nullptr;
    tmsize_t tilesize = 0;
    tmsize_t readsize = 0;
    tmsize_t writesize = 0;
    uint32 tile = 0;
    int result = 0;

    // Initialize the TIFF object in memory
    tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Check if the TIFF image can be converted to RGBA format
    if (!TIFFRGBAImageOK(tif, emsg)) {
        freeTIFF(tif);
        return 0;
    }

    // Calculate the size of a TIFF strip
    tilesize = TIFFVStripSize(tif, 1);
    if (tilesize <= 0) {
        freeTIFF(tif);
        return 0;
    }

    // Allocate buffer for reading and writing tiles
    buf = malloc(tilesize);
    if (!buf) {
        freeTIFF(tif);
        return 0;
    }

    // Read an encoded tile
    tile = 0; // Assuming the first tile
    readsize = TIFFReadEncodedTile(tif, tile, buf, tilesize);
    if (readsize == (tmsize_t)(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0;
    }

    // Write the encoded tile back to the TIFF object
    writesize = TIFFWriteEncodedTile(tif, tile, buf, readsize);
    if (writesize == (tmsize_t)(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0;
    }

    // Flush the TIFF object to ensure all data is written
    result = TIFFFlush(tif);
    if (!result) {
        free(buf);
        freeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    free(buf);
    freeTIFF(tif);

    return 0;
}
