#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::stringstream

// Function to safely convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert fuzz input to a uint32_t
uint32_t fuzzInputToUint32(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(uint32_t) > size) return 0;
    return *((uint32_t*)(data + offset));
}

// Function to safely convert fuzz input to a uint16_t
uint16_t fuzzInputToUint16(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(uint16_t) > size) return 0;
    return *((uint16_t*)(data + offset));
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(uint32_t) + sizeof(uint16_t)) return 0;

    // Convert fuzz input to a string for TIFFStreamOpen
    char* tiffData = fuzzInputToString(data, size);
    if (!tiffData) return 0;

    // Open TIFF stream in memory
    std::stringstream ss(tiffData);
    TIFF* tif = TIFFStreamOpen("MemTIFF", static_cast<std::ostream*>(&ss)); // Explicitly cast to std::ostream*
    if (!tif) {
        free(tiffData);
        return 0;
    }

    // Extract values from fuzz input for API calls
    uint32_t tag = fuzzInputToUint32(data, size, 0);
    uint16_t tagIndex = fuzzInputToUint16(data, size, sizeof(uint32_t));

    // Call TIFFSetClientInfo
    void* clientData = (void*)data; // Use the fuzz input as client data
    TIFFSetClientInfo(tif, clientData, "FuzzClient");

    // Call TIFFGetField
    uint32_t value;
    if (TIFFGetField(tif, tag, &value)) {
        // Handle the retrieved value if needed
    }

    // Call TIFFGetFieldDefaulted
    uint32_t defaultValue;
    if (TIFFGetFieldDefaulted(tif, tag, &defaultValue)) {
        // Handle the default value if needed
    }

    // Call TIFFGetTagListEntry
    uint32_t tagEntry = TIFFGetTagListEntry(tif, tagIndex);
    if (tagEntry != (uint32_t)(-1)) {
        // Handle the tag entry if needed
    }

    // Call TIFFRewriteDirectory
    if (TIFFRewriteDirectory(tif)) {
        // Handle successful directory rewrite if needed
    }

    // Close the TIFF stream and free resources
    TIFFClose(tif);
    free(tiffData);

    return 0;
}
