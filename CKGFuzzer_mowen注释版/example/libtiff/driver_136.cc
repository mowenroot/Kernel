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

// Function to create a TIFF object from a string
TIFF* CreateTIFFFromString(const std::string& tiffData) {
    std::istringstream s(tiffData); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated resources
void FreeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string tiffData = FuzzInputToString(data, size);

    // Create a TIFF object from the string
    TIFF* tif = CreateTIFFFromString(tiffData);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Variables for API calls
    uint64_t* longArray = nullptr;
    tmsize_t longArraySize = 0;
    uint32_t row = 0;
    uint16_t sample = 0;
    uint32_t strip = 0;
    tmsize_t stripSize = 0;
    toff_t diroff = 0;
    const TIFFFieldArray* infoarray = nullptr;

    // Allocate memory for longArray
    if (size >= sizeof(uint64_t)) {
        longArraySize = size / sizeof(uint64_t);
        longArray = static_cast<uint64_t*>(malloc(longArraySize * sizeof(uint64_t)));
        if (!longArray) {
            FreeTIFF(tif);
            return 0; // Memory allocation failed
        }
        memcpy(longArray, data, longArraySize * sizeof(uint64_t));
    }

    // Call TIFFSwabArrayOfLong8
    if (longArray) {
        TIFFSwabArrayOfLong8(longArray, longArraySize);
    }

    // Call TIFFReadScanline
    if (size >= sizeof(uint32_t)) {
        row = *reinterpret_cast<const uint32_t*>(data);
        sample = *reinterpret_cast<const uint16_t*>(data + sizeof(uint32_t));
        uint8_t scanlineBuffer[1024]; // Define a reasonable buffer size
        if (TIFFReadScanline(tif, scanlineBuffer, row, sample) < 0) {
            // Handle error
        }
    }

    // Call TIFFReadRawStrip
    if (size >= sizeof(uint32_t)) {
        strip = *reinterpret_cast<const uint32_t*>(data);
        stripSize = size;
        uint8_t stripBuffer[1024]; // Define a reasonable buffer size
        if (TIFFReadRawStrip(tif, strip, stripBuffer, stripSize) < 0) {
            // Handle error
        }
    }

    // Call TIFFGetBitRevTable
    int reversed = (size > 0) ? (data[0] % 2) : 0;
    const unsigned char* bitRevTable = TIFFGetBitRevTable(reversed);

    // Call TIFFReadCustomDirectory
    if (size >= sizeof(toff_t)) {
        diroff = *reinterpret_cast<const toff_t*>(data);
        if (TIFFReadCustomDirectory(tif, diroff, infoarray) == 0) {
            // Handle error
        }
    }

    // Free allocated memory
    if (longArray) {
        free(longArray);
    }

    // Free the TIFF object
    FreeTIFF(tif);

    return 0; // Return 0 to indicate success
}
