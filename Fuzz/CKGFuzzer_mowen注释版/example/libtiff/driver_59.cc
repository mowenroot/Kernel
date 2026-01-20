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

    // Create a TIFF stream in memory
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
    TIFFRGBAImage img;
    char emsg[1024];
    int result = 0;

    // Create a TIFF object in memory from the fuzz input
    tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0; // Early exit if TIFF creation fails
    }

    // Initialize TIFFRGBAImage structure
    if (TIFFRGBAImageBegin(&img, tif, 0, emsg)) {
        // Read raw tile data
        uint32 tile = 0; // Assuming tile index 0 for simplicity
        tmsize_t tileSize = TIFFTileSize(tif);
        if (tileSize > 0) {
            void* buf = _TIFFmalloc(tileSize);
            if (buf) {
                tmsize_t readSize = TIFFReadRawTile(tif, tile, buf, tileSize);
                if (readSize != (tmsize_t)(-1)) {
                    // Compare the read data with the original data
                    if (_TIFFmemcmp(data, buf, readSize) == 0) {
                        result = 1; // Data matches
                    }
                }
                _TIFFfree(buf);
            }
        }

        // Unlink a directory (assuming directory index 0 for simplicity)
        if (TIFFUnlinkDirectory(tif, 0)) {
            // Flush data to ensure consistency
            if (TIFFFlushData(tif)) {
                result = 1; // Successfully flushed data
            }
        }

        // Clean up TIFFRGBAImage structure
        TIFFRGBAImageEnd(&img);
    }

    // Free the TIFF object
    freeTIFF(tif);

    return result;
}
