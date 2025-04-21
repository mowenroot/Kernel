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

// Function to create a TIFF object in memory from a string
TIFF* CreateTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s);
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated memory
void FreeTIFFInMemory(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Variables for API calls
    uint32 tile = 0;
    tmsize_t tileSize = 1024; // Arbitrary size for the tile buffer
    void* tileBuffer = malloc(tileSize);
    if (!tileBuffer) {
        FreeTIFFInMemory(tif);
        return 0; // Failed to allocate memory for tile buffer
    }

    // Call TIFFReadRawTile
    tmsize_t readSize = TIFFReadRawTile(tif, tile, tileBuffer, tileSize);
    if (readSize == static_cast<tmsize_t>(-1)) {
        free(tileBuffer);
        FreeTIFFInMemory(tif);
        return 0; // Error in reading raw tile
    }

    // Call TIFFSwabArrayOfFloat
    TIFFSwabArrayOfFloat(reinterpret_cast<float*>(tileBuffer), readSize / sizeof(float));

    // Call TIFFSwabArrayOfShort
    TIFFSwabArrayOfShort(reinterpret_cast<uint16_t*>(tileBuffer), readSize / sizeof(uint16_t));

    // Call TIFFGetBitRevTable
    const unsigned char* bitRevTable = TIFFGetBitRevTable(1);
    if (!bitRevTable) {
        free(tileBuffer);
        FreeTIFFInMemory(tif);
        return 0; // Error in getting bit reversal table
    }

    // Call TIFFReadCustomDirectory
    toff_t diroff = 0; // Arbitrary offset for custom directory
    const TIFFFieldArray* infoarray = nullptr; // Assuming no custom field array
    int result = TIFFReadCustomDirectory(tif, diroff, infoarray);
    if (result != 1) {
        free(tileBuffer);
        FreeTIFFInMemory(tif);
        return 0; // Error in reading custom directory
    }

    // Free allocated resources
    free(tileBuffer);
    FreeTIFFInMemory(tif);

    return 0; // Success
}
