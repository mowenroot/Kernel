#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string fuzzInputToString(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        fprintf(stderr, "Failed to create TIFF object in memory\n");
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzData = fuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = createTIFFInMemory(fuzzData);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint64_t* longArray = nullptr;
    tmsize_t longArraySize = 0;
    uint16_t dirn = 0;
    uint32_t tile = 0;
    void* buf = nullptr;
    tmsize_t bufSize = 0;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size >= sizeof(uint64_t) * 2 + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(tmsize_t)) {
        longArraySize = size / sizeof(uint64_t);
        longArray = static_cast<uint64_t*>(malloc(longArraySize * sizeof(uint64_t)));
        if (!longArray) {
            TIFFClose(tif);
            return 0;
        }
        memcpy(longArray, data, longArraySize * sizeof(uint64_t));

        dirn = *reinterpret_cast<const uint16_t*>(data + longArraySize * sizeof(uint64_t));
        tile = *reinterpret_cast<const uint32_t*>(data + longArraySize * sizeof(uint64_t) + sizeof(uint16_t));
        bufSize = *reinterpret_cast<const tmsize_t*>(data + longArraySize * sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint32_t));
        buf = malloc(bufSize);
        if (!buf) {
            free(longArray);
            TIFFClose(tif);
            return 0;
        }
    }

    // Call TIFFSwabArrayOfLong8
    if (longArray) {
        TIFFSwabArrayOfLong8(longArray, longArraySize);
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        fprintf(stderr, "TIFFFlushData failed\n");
    }

    // Call TIFFUnlinkDirectory
    if (TIFFUnlinkDirectory(tif, dirn) != 1) {
        fprintf(stderr, "TIFFUnlinkDirectory failed\n");
    }

    // Call TIFFReadRawTile
    if (buf) {
        if (TIFFReadRawTile(tif, tile, buf, bufSize) == static_cast<tmsize_t>(-1)) {
            fprintf(stderr, "TIFFReadRawTile failed\n");
        }
    }

    // Call TIFFGetTagListCount
    int tagCount = TIFFGetTagListCount(tif);
    if (tagCount < 0) {
        fprintf(stderr, "TIFFGetTagListCount failed\n");
    }

    // Free allocated resources
    free(longArray);
    free(buf);
    TIFFClose(tif);

    return 0;
}
