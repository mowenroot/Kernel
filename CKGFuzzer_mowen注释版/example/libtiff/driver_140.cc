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
        return 0; // Failed to create TIFF object
    }

    // Initialize variables
    uint32_t tile = 0;
    void* buf = malloc(size);
    if (!buf) {
        freeTIFF(tif);
        return 0; // Failed to allocate buffer
    }

    // Call TIFFSetClientInfo
    TIFFSetClientInfo(tif, buf, "fuzz_client_info");

    // Call TIFFReadEncodedTile
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buf, size);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to read tile
    }

    // Call TIFFWriteEncodedTile
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, buf, readSize);
    if (writeSize == static_cast<tmsize_t>(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to write tile
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) != 1) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to flush data
    }

    // Call TIFFRewriteDirectory
    if (TIFFRewriteDirectory(tif) != 1) {
        free(buf);
        freeTIFF(tif);
        return 0; // Failed to rewrite directory
    }

    // Free allocated resources
    free(buf);
    freeTIFF(tif);

    return 0; // Success
}
