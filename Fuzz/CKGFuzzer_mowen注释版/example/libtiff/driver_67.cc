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
    TIFF* tif = nullptr;
    char emsg[1024] = {0};
    int result = 0;

    // Create a TIFF object in memory from the fuzz input
    tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0; // Early exit if TIFF creation fails
    }

    // Call TIFFRGBAImageOK to check if the image can be converted to RGBA format
    if (TIFFRGBAImageOK(tif, emsg)) {
        // If the image is OK, proceed with other operations

        // Call TIFFDataWidth to get the data width of a TIFF data type
        int dataWidth = TIFFDataWidth(TIFF_BYTE);
        if (dataWidth <= 0) {
            freeTIFF(tif);
            return 0; // Early exit if data width is invalid
        }

        // Allocate a buffer for reading/writing raw tile data
        uint8_t* buffer = (uint8_t*)malloc(size);
        if (!buffer) {
            freeTIFF(tif);
            return 0; // Early exit if memory allocation fails
        }

        // Call TIFFReadRawTile to read raw tile data
        tmsize_t readSize = TIFFReadRawTile(tif, 0, buffer, size);
        if (readSize == (tmsize_t)(-1)) {
            free(buffer);
            freeTIFF(tif);
            return 0; // Early exit if reading fails
        }

        // Call TIFFWriteRawTile to write raw tile data
        tmsize_t writeSize = TIFFWriteRawTile(tif, 0, buffer, readSize);
        if (writeSize == (tmsize_t)(-1)) {
            free(buffer);
            freeTIFF(tif);
            return 0; // Early exit if writing fails
        }

        // Call TIFFFlushData to ensure data integrity
        result = TIFFFlushData(tif);
        if (result != 1) {
            free(buffer);
            freeTIFF(tif);
            return 0; // Early exit if flushing fails
        }

        // Free the buffer
        free(buffer);
    }

    // Free the TIFF object
    freeTIFF(tif);

    return 0; // Return 0 to indicate success
}
