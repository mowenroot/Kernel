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
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
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
    tmsize_t cc = 0;
    void* buf = nullptr;
    TIFFCIELabToRGB cielab;
    float X, Y, Z;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size < sizeof(uint32_t) + sizeof(tmsize_t)) {
        freeTIFF(tif);
        return 0; // Insufficient data
    }

    // Derive API inputs from fuzz driver inputs
    tile = *reinterpret_cast<const uint32_t*>(data);
    cc = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32_t));
    buf = malloc(cc);
    if (!buf) {
        freeTIFF(tif);
        return 0; // Memory allocation failed
    }

    // Call TIFFWriteRawTile
    tmsize_t writeResult = TIFFWriteRawTile(tif, tile, buf, cc);
    if (writeResult == static_cast<tmsize_t>(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0; // Error in writing raw tile
    }

    // Call TIFFUnlinkDirectory
    uint16_t dirn = 1; // Example directory number
    int unlinkResult = TIFFUnlinkDirectory(tif, dirn);
    if (!unlinkResult) {
        free(buf);
        freeTIFF(tif);
        return 0; // Error in unlinking directory
    }

    // Call TIFFReadRawTile
    tmsize_t readResult = TIFFReadRawTile(tif, tile, buf, cc);
    if (readResult == static_cast<tmsize_t>(-1)) {
        free(buf);
        freeTIFF(tif);
        return 0; // Error in reading raw tile
    }

    // Call TIFFSetClientInfo
    void* clientData = const_cast<void*>(reinterpret_cast<const void*>(data)); // Corrected cast
    const char* clientName = "fuzz_client";
    TIFFSetClientInfo(tif, clientData, clientName);

    // Call TIFFCIELabToXYZ
    uint32_t l = 50; // Example L value
    int32_t a = 0;   // Example a value
    int32_t b = 0;   // Example b value
    TIFFCIELabToXYZ(&cielab, l, a, b, &X, &Y, &Z);

    // Free allocated resources
    free(buf);
    freeTIFF(tif);

    return 0; // Success
}
