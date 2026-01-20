#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF stream in memory
TIFF* createTIFFStream(const uint8_t* data, size_t size) {
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

// Custom warning handler to capture TIFF warnings
static void customWarningHandler(const char* module, const char* fmt, va_list ap) {
    // Log or handle the warning as needed
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, ap);
    // Example: fprintf(stderr, "TIFF Warning: %s\n", buffer);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    TIFF* tif = nullptr;
    char emsg[1024] = {0};
    void* buffer = nullptr;
    tmsize_t bufferSize = 0;
    int result = 0;

    // Create a TIFF stream from the fuzz input
    tif = createTIFFStream(data, size);
    if (!tif) {
        return 0; // Early exit if TIFF stream creation fails
    }

    // Set custom warning handler
    TIFFSetWarningHandler(customWarningHandler);

    // Check if the TIFF image can be converted to RGBA format
    if (TIFFRGBAImageOK(tif, emsg)) {
        // Allocate buffer for reading encoded strip
        bufferSize = TIFFStripSize(tif);
        if (bufferSize > 0) {
            buffer = malloc(bufferSize);
            if (!buffer) {
                TIFFClose(tif);
                return 0; // Early exit if buffer allocation fails
            }

            // Read encoded strip
            tmsize_t readSize = TIFFReadEncodedStrip(tif, 0, buffer, bufferSize);
            if (readSize == (tmsize_t)(-1)) {
                // Handle error
            }

            // Read raw tile
            tmsize_t rawTileSize = TIFFReadRawTile(tif, 0, buffer, bufferSize);
            if (rawTileSize == (tmsize_t)(-1)) {
                // Handle error
            }
        }
    } else {
        // Handle the case where RGBA conversion is not possible
    }

    // Flush data to ensure consistency
    if (TIFFFlushData(tif) != 1) {
        // Handle error
    }

    // Clean up
    if (buffer) {
        free(buffer);
    }
    TIFFClose(tif);

    return 0; // Return 0 to indicate success
}
