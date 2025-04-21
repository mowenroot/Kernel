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
TIFF* createTIFFInMemory(const char* data) {
    std::istringstream s(data); // Use std::istringstream instead of passing raw data
    TIFF* tif = TIFFStreamOpen("memory", &s); // Pass the address of the istringstream
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
    TIFF* tif = createTIFFInMemory(inputStr);
    if (tif == NULL) {
        free(inputStr);
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    uint16 dirn = 0;
    void* buf = malloc(size);
    if (buf == NULL) {
        TIFFClose(tif);
        free(inputStr);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t readSize = TIFFReadRawTile(tif, tile, buf, size);
    if (readSize == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFUnlinkDirectory
    int unlinkResult = TIFFUnlinkDirectory(tif, dirn);
    if (unlinkResult == 0) {
        // Handle error
    }

    // Call TIFFSetClientInfo
    TIFFSetClientInfo(tif, buf, "fuzz_client_info");

    // Call TIFFFlush
    int flushResult = TIFFFlush(tif);
    if (flushResult == 0) {
        // Handle error
    }

    // Call TIFFWriteRawStrip
    tmsize_t writeSize = TIFFWriteRawStrip(tif, tile, buf, size);
    if (writeSize == (tmsize_t)(-1)) {
        // Handle error
    }

    // Free allocated resources
    free(buf);
    TIFFClose(tif);
    free(inputStr);

    return 0;
}
