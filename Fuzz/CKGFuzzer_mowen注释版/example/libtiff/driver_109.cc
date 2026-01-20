#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to create a TIFF object in memory from a string
TIFF* createTIFFFromString(const char* str) {
    std::istringstream s(str); // Use std::istringstream instead of std::string
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (tif == NULL) {
        return NULL;
    }
    return tif;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* inputStr = fuzzInputToString(data, size);
    if (inputStr == NULL) {
        return 0;
    }

    // Create a TIFF object in memory
    TIFF* tif = createTIFFFromString(inputStr);
    if (tif == NULL) {
        free(inputStr);
        return 0;
    }

    // Initialize variables
    int lastDir = 0;
    tmsize_t readSize = 0;
    uint32 tileIndex = 0;
    void* buffer = NULL;

    // Set client info
    TIFFSetClientInfo(tif, (void*)inputStr, "FuzzClientInfo");

    // Check if it's the last directory
    lastDir = TIFFLastDirectory(tif);

    // Read raw tile data
    tileIndex = 0; // Assuming tile index 0 for simplicity
    buffer = malloc(size);
    if (buffer != NULL) {
        readSize = TIFFReadRawTile(tif, tileIndex, buffer, size);
        if (readSize == (tmsize_t)(-1)) {
            // Handle error
        }
        free(buffer);
    }

    // Flush data
    if (TIFFFlushData(tif) != 1) {
        // Handle error
    }

    // Close TIFF object
    TIFFClose(tif);

    // Free allocated memory
    free(inputStr);

    return 0;
}
