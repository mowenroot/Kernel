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
    std::string fuzzInput = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    void* buf = nullptr;
    tmsize_t bufSize = 0;
    tmsize_t writeSize = 0;
    uint16 dirn = 0;
    uint64 stripSize = 0;

    // Ensure proper bounds checking
    if (size < sizeof(uint32) + sizeof(tmsize_t) + sizeof(uint16)) {
        freeTIFF(tif);
        return 0;
    }

    // Derive API inputs from fuzz input
    tile = *reinterpret_cast<const uint32*>(data);
    data += sizeof(uint32);
    size -= sizeof(uint32);

    bufSize = *reinterpret_cast<const tmsize_t*>(data);
    data += sizeof(tmsize_t);
    size -= sizeof(tmsize_t);

    dirn = *reinterpret_cast<const uint16*>(data);
    data += sizeof(uint16);
    size -= sizeof(uint16);

    // Allocate buffer for reading/writing
    buf = malloc(bufSize);
    if (!buf) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteRawTile
    writeSize = TIFFWriteRawTile(tif, tile, buf, bufSize);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t readSize = TIFFReadRawTile(tif, tile, buf, bufSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFUnlinkDirectory
    int unlinkResult = TIFFUnlinkDirectory(tif, dirn);
    if (!unlinkResult) {
        free(buf);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFStripSize64
    stripSize = TIFFStripSize64(tif);

    // Call TIFFFlush
    int flushResult = TIFFFlush(tif);
    if (!flushResult) {
        free(buf);
        freeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    free(buf);
    freeTIFF(tif);

    return 0;
}
