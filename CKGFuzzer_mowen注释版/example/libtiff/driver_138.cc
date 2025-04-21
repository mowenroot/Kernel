#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* createTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF object in memory
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
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32_t) * 3) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize variables for API calls
    char emsg[1024];
    uint32_t tile = *(uint32_t*)(data + sizeof(uint32_t));
    tmsize_t cc = *(tmsize_t*)(data + 2 * sizeof(uint32_t));
    void* buf = malloc(cc);
    if (!buf) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA
    int rgbaOK = TIFFRGBAImageOK(tif, emsg);
    if (rgbaOK) {
        // Call TIFFWriteRawTile to write raw tile data
        tmsize_t writeResult = TIFFWriteRawTile(tif, tile, buf, cc);
        if (writeResult == (tmsize_t)(-1)) {
            // Handle error
        }

        // Call TIFFReadRawTile to read raw tile data
        tmsize_t readResult = TIFFReadRawTile(tif, tile, buf, cc);
        if (readResult == (tmsize_t)(-1)) {
            // Handle error
        }
    }

    // Call TIFFFlushData to flush data to the file
    int flushResult = TIFFFlushData(tif);
    if (flushResult == 0) {
        // Handle error
    }

    // Free allocated memory
    free(buf);
    freeTIFF(tif);

    return 0;
}
