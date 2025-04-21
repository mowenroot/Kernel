#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
std::string FuzzInputToString(const uint8_t *data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Function to create a TIFF object in memory from the fuzz input
TIFF* CreateTIFFInMemory(const uint8_t *data, size_t size) {
    std::string input = FuzzInputToString(data, size);
    std::istringstream s(input); // Use std::istringstream instead of std::stringstream
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) {
        // Insufficient data to perform meaningful operations
        return 0;
    }

    TIFF* tif = nullptr;
    void* buf = nullptr;
    int result = 0;

    try {
        // Create a TIFF object in memory from the fuzz input
        tif = CreateTIFFInMemory(data, size);
        if (!tif) {
            return 0; // Failed to create TIFF object
        }

        // Extract parameters from fuzz input
        uint32_t tile = *reinterpret_cast<const uint32_t*>(data);
        uint32_t row = *reinterpret_cast<const uint32_t*>(data + 4);
        uint16_t sample = *reinterpret_cast<const uint16_t*>(data + 8);
        tmsize_t bufSize = *reinterpret_cast<const tmsize_t*>(data + 10);

        // Allocate buffer for reading/writing
        buf = malloc(bufSize);
        if (!buf) {
            throw std::runtime_error("Failed to allocate buffer");
        }

        // Call TIFFWriteRawTile
        tmsize_t writeResult = TIFFWriteRawTile(tif, tile, buf, bufSize);
        if (writeResult == static_cast<tmsize_t>(-1)) {
            throw std::runtime_error("TIFFWriteRawTile failed");
        }

        // Call TIFFReadScanline
        int readScanlineResult = TIFFReadScanline(tif, buf, row, sample);
        if (readScanlineResult == -1) {
            throw std::runtime_error("TIFFReadScanline failed");
        }

        // Call TIFFReadRawTile
        tmsize_t readRawTileResult = TIFFReadRawTile(tif, tile, buf, bufSize);
        if (readRawTileResult == static_cast<tmsize_t>(-1)) {
            throw std::runtime_error("TIFFReadRawTile failed");
        }

        // Call TIFFFlushData
        int flushResult = TIFFFlushData(tif);
        if (flushResult == 0) {
            throw std::runtime_error("TIFFFlushData failed");
        }

        // Call TIFFGetClientInfo (example usage)
        void* clientInfo = TIFFGetClientInfo(tif, "ExampleClientInfo");
        if (clientInfo) {
            // Handle client info if needed
        }

    } catch (const std::exception& e) {
        // Log the error (in a real fuzzer, this would be handled by the fuzzing engine)
        result = 1;
    }

    // Clean up
    if (buf) {
        free(buf);
    }
    if (tif) {
        TIFFClose(tif);
    }

    return result;
}
