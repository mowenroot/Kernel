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

// Function to create a TIFF object from a string
TIFF* createTIFFFromString(const char* str) {
    std::istringstream s(str); // Use std::istringstream instead of new std::string(str)
    return TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    char* inputStr = fuzzInputToString(data, size);
    if (inputStr == NULL) {
        return 0;
    }

    // Create a TIFF object from the string
    TIFF* tif = createTIFFFromString(inputStr);
    if (tif == NULL) {
        free(inputStr);
        return 0;
    }

    // Initialize variables
    uint32 tile = 0;
    void* buf = NULL;
    tmsize_t bufSize = 0;
    uint16 dirn = 0;
    void* clientData = NULL;
    const char* clientName = "FuzzClient";
    TIFFExtendProc extender = NULL;

    // Extract values from fuzz input
    if (size >= 8) {
        tile = *((uint32*)data);
        dirn = *((uint16*)(data + 4));
        bufSize = *((tmsize_t*)(data + 6));
    }

    // Allocate buffer for TIFFReadRawTile
    if (bufSize > 0) {
        buf = malloc(bufSize);
        if (buf == NULL) {
            TIFFClose(tif);
            free(inputStr);
            return 0;
        }
    }

    // Call TIFFReadRawTile
    tmsize_t bytesRead = TIFFReadRawTile(tif, tile, buf, bufSize);
    if (bytesRead == (tmsize_t)(-1)) {
        // Handle error
    }

    // Call TIFFUnlinkDirectory
    int unlinkResult = TIFFUnlinkDirectory(tif, dirn);
    if (unlinkResult == 0) {
        // Handle error
    }

    // Call TIFFSetClientInfo
    TIFFSetClientInfo(tif, clientData, clientName);

    // Call TIFFFlush
    int flushResult = TIFFFlush(tif);
    if (flushResult == 0) {
        // Handle error
    }

    // Call TIFFSetTagExtender
    TIFFExtendProc prevExtender = TIFFSetTagExtender(extender);

    // Free allocated resources
    if (buf != NULL) {
        free(buf);
    }
    TIFFClose(tif);
    free(inputStr);

    return 0;
}
