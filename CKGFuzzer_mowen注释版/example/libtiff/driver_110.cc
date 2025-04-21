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

// Function to create a TIFF object in memory from the fuzz input
TIFF* CreateTIFFInMemory(const std::string& fuzzInput) {
    // Create a TIFF object in memory
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        TIFFError("CreateTIFFInMemory", "Failed to create TIFF object in memory");
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
    std::string fuzzInput = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzzInput);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint16_t numDirectories = 0;
    uint32_t tileIndex = 0;
    tmsize_t tileSize = 0;
    void* tileBuffer = nullptr;
    TIFFRGBAImage img;
    uint32_t raster[1]; // Dummy raster buffer

    // Call TIFFNumberOfDirectories
    numDirectories = TIFFNumberOfDirectories(tif);
    if (numDirectories == 65535) {
        TIFFWarning("LLVMFuzzerTestOneInput", "Directory count exceeded 65535 limit");
    }

    // Call TIFFWriteRawTile
    tileIndex = static_cast<uint32_t>(data[0]); // Use the first byte of fuzz input as tile index
    tileSize = static_cast<tmsize_t>(data[1]); // Use the second byte of fuzz input as tile size
    if (tileSize > 0) {
        tileBuffer = malloc(tileSize);
        if (tileBuffer) {
            memset(tileBuffer, 0, tileSize);
            tmsize_t writtenSize = TIFFWriteRawTile(tif, tileIndex, tileBuffer, tileSize);
            if (writtenSize == static_cast<tmsize_t>(-1)) {
                TIFFWarning("LLVMFuzzerTestOneInput", "Failed to write raw tile");
            }
            free(tileBuffer);
        }
    }

    // Call TIFFReadRawTile
    tileIndex = static_cast<uint32_t>(data[2]); // Use the third byte of fuzz input as tile index
    tileSize = static_cast<tmsize_t>(data[3]); // Use the fourth byte of fuzz input as tile size
    if (tileSize > 0) {
        tileBuffer = malloc(tileSize);
        if (tileBuffer) {
            memset(tileBuffer, 0, tileSize);
            tmsize_t readSize = TIFFReadRawTile(tif, tileIndex, tileBuffer, tileSize);
            if (readSize == static_cast<tmsize_t>(-1)) {
                TIFFWarning("LLVMFuzzerTestOneInput", "Failed to read raw tile");
            }
            free(tileBuffer);
        }
    }

    // Call TIFFRGBAImageGet
    if (TIFFRGBAImageBegin(&img, tif, 0, nullptr) == 1) {
        int result = TIFFRGBAImageGet(&img, raster, 1, 1);
        if (result == 0) {
            TIFFWarning("LLVMFuzzerTestOneInput", "Failed to get RGBA image");
        }
        TIFFRGBAImageEnd(&img);
    } else {
        TIFFWarning("LLVMFuzzerTestOneInput", "Failed to begin RGBA image");
    }

    // Free the TIFF object and associated resources
    FreeTIFF(tif);

    return 0;
}
