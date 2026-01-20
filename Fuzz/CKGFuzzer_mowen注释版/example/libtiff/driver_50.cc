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
    // Create a TIFF object in memory
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string input = fuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(input);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t tile = 0;
    void* buf = nullptr;
    tmsize_t bufSize = 0;
    int status = 0;

    // Ensure proper memory management
    try {
        // Example usage of TIFFSetClientInfo
        TIFFSetClientInfo(tif, nullptr, "FuzzTest");

        // Example usage of TIFFReadRawTile
        bufSize = TIFFTileSize(tif);
        if (bufSize > 0) {
            buf = _TIFFmalloc(bufSize);
            if (!buf) {
                throw std::runtime_error("Failed to allocate buffer");
            }
            tmsize_t readSize = TIFFReadRawTile(tif, tile, buf, bufSize);
            if (readSize == static_cast<tmsize_t>(-1)) {
                throw std::runtime_error("TIFFReadRawTile failed");
            }
        }

        // Example usage of TIFFWriteScanline
        uint32_t row = 0;
        uint16_t sample = 0;
        if (bufSize > 0) {
            status = TIFFWriteScanline(tif, buf, row, sample);
            if (status == -1) {
                throw std::runtime_error("TIFFWriteScanline failed");
            }
        }

        // Example usage of TIFFFlushData
        status = TIFFFlushData(tif);
        if (status == 0) {
            throw std::runtime_error("TIFFFlushData failed");
        }

        // Example usage of TIFFRewriteDirectory
        status = TIFFRewriteDirectory(tif);
        if (status == 0) {
            throw std::runtime_error("TIFFRewriteDirectory failed");
        }

    } catch (const std::exception& e) {
        // Handle exceptions and errors
        TIFFErrorExt(tif, "FuzzDriver", "%s", e.what());
    }

    // Free allocated resources
    if (buf) {
        _TIFFfree(buf);
    }
    TIFFClose(tif);

    return 0;
}
