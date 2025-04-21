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

// Function to create a TIFF object in memory from the fuzz input
TIFF* CreateTIFFInMemory(const uint8_t* data, size_t size) {
    std::string input = FuzzInputToString(data, size);
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("mem", &s); // Pass the address of the istringstream
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    void* buffer = nullptr;
    tmsize_t bufferSize = 0;
    uint32 tile = 0;
    tmsize_t readSize = 0;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32) + sizeof(tmsize_t)) {
        return 0;
    }

    // Initialize variables from fuzz input
    tile = *reinterpret_cast<const uint32*>(data);
    data += sizeof(uint32);
    size -= sizeof(uint32);

    bufferSize = *reinterpret_cast<const tmsize_t*>(data);
    data += sizeof(tmsize_t);
    size -= sizeof(tmsize_t);

    // Create TIFF object in memory
    tif = CreateTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Setup read buffer
    if (!TIFFReadBufferSetup(tif, nullptr, bufferSize)) {
        TIFFClose(tif);
        return 0;
    }

    // Allocate buffer for reading tile data
    buffer = _TIFFmalloc(bufferSize);
    if (!buffer) {
        TIFFClose(tif);
        return 0;
    }

    // Read encoded tile
    readSize = TIFFReadEncodedTile(tif, tile, buffer, bufferSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        _TIFFfree(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Setup write buffer
    if (!TIFFWriteBufferSetup(tif, nullptr, bufferSize)) {
        _TIFFfree(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Flush data to ensure consistency
    if (TIFFFlushData(tif) != 1) {
        _TIFFfree(buffer);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    _TIFFfree(buffer);
    TIFFClose(tif);

    return 0;
}
