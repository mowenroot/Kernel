#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream
#include <assert.h>

// Function to create a TIFF object in memory from the fuzz input
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput = std::string(reinterpret_cast<const char*>(data), size);

    // Create a TIFF object in memory
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object
void freeTIFF(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(uint32_t) + sizeof(uint16_t)) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint32_t longValue = 0;
    uint16_t shortValue = 0;
    uint32_t* longArray = nullptr;
    uint16_t* shortArray = nullptr;
    tmsize_t arraySize = 0;

    // Extract values from the fuzz input
    memcpy(&longValue, data, sizeof(uint32_t));
    memcpy(&shortValue, data + sizeof(uint32_t), sizeof(uint16_t));

    // Allocate memory for arrays
    arraySize = size / (sizeof(uint32_t) + sizeof(uint16_t));
    longArray = (uint32_t*)malloc(arraySize * sizeof(uint32_t));
    shortArray = (uint16_t*)malloc(arraySize * sizeof(uint16_t));

    if (!longArray || !shortArray) {
        freeTIFF(tif);
        free(longArray);
        free(shortArray);
        return 0;
    }

    // Initialize arrays with values from the fuzz input
    for (tmsize_t i = 0; i < arraySize; ++i) {
        memcpy(&longArray[i], data + i * (sizeof(uint32_t) + sizeof(uint16_t)), sizeof(uint32_t));
        memcpy(&shortArray[i], data + i * (sizeof(uint32_t) + sizeof(uint16_t)) + sizeof(uint32_t), sizeof(uint16_t));
    }

    // Call the APIs
    TIFFSwabLong(&longValue);
    TIFFSwabShort(&shortValue);
    TIFFSwabArrayOfLong(longArray, arraySize);
    TIFFSwabArrayOfShort(shortArray, arraySize);

    // Check endianness and byte-swapping
    int isBigEndian = TIFFIsBigEndian(tif);
    int isByteSwapped = TIFFIsByteSwapped(tif);

    // Free allocated memory
    free(longArray);
    free(shortArray);

    // Free the TIFF object
    freeTIFF(tif);

    return 0;
}
