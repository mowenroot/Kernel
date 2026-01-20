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

// Custom error handler
static void CustomErrorHandler(const char* module, const char* fmt, va_list ap) {
    // Custom error handling logic can be added here
    vfprintf(stderr, fmt, ap);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = FuzzInputToString(data, size);

    // Initialize TIFF object in memory
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        return 0; // Failed to initialize TIFF object
    }

    // Set custom error handler
    TIFFSetErrorHandler(CustomErrorHandler);

    // Prepare data for TIFFSwabArrayOfLong8
    uint64_t* longArray = nullptr;
    tmsize_t longArraySize = 0;
    if (size >= sizeof(uint64_t)) {
        longArraySize = size / sizeof(uint64_t);
        longArray = static_cast<uint64_t*>(malloc(longArraySize * sizeof(uint64_t)));
        if (longArray) {
            memcpy(longArray, data, longArraySize * sizeof(uint64_t));
            TIFFSwabArrayOfLong8(longArray, longArraySize);
        }
    }

    // Prepare data for TIFFWriteRawTile
    uint32_t tileIndex = 0;
    if (size >= sizeof(uint32_t)) {
        tileIndex = *reinterpret_cast<const uint32_t*>(data);
    }
    tmsize_t dataSize = size;
    tmsize_t writtenSize = TIFFWriteRawTile(tif, tileIndex, const_cast<uint8_t*>(data), dataSize);
    if (writtenSize == static_cast<tmsize_t>(-1)) {
        // Handle error
    }

    // Prepare buffer for TIFFReadRawTile
    uint8_t* readBuffer = static_cast<uint8_t*>(malloc(dataSize));
    if (readBuffer) {
        tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, readBuffer, dataSize);
        if (readSize == static_cast<tmsize_t>(-1)) {
            // Handle error
        }
        free(readBuffer);
    }

    // Flush data
    if (TIFFFlushData(tif) != 1) {
        // Handle error
    }

    // Free allocated memory
    if (longArray) {
        free(longArray);
    }

    // Close TIFF object
    TIFFClose(tif);

    return 0;
}
