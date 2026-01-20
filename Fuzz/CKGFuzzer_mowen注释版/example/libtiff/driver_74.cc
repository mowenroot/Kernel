#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF object in memory
TIFF* CreateTIFFInMemory(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Function to free the TIFF object and associated memory
void FreeTIFFInMemory(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = CreateTIFFInMemory(data, size);
    if (!tif) {
        return 0; // Failed to create TIFF object
    }

    // Variables for API calls
    uint32 tile = 0;
    void* buf = nullptr;
    tmsize_t buf_size = 0;
    int result = 0;

    // Ensure proper initialization of variables
    tile = (size > 0) ? data[0] % 10 : 0; // Arbitrary tile number, max 10
    buf_size = (size > 4) ? *(reinterpret_cast<const uint32_t*>(data + 1)) : 0;
    if (buf_size > 0) {
        buf = malloc(buf_size);
        if (!buf) {
            FreeTIFFInMemory(tif);
            return 0; // Allocation failed
        }
    }

    // Call TIFFFlushData
    result = TIFFFlushData(tif);
    if (result != 1) {
        // Handle error
        free(buf);
        FreeTIFFInMemory(tif);
        return 0;
    }

    // Call TIFFReadEncodedTile
    tmsize_t read_size = TIFFReadEncodedTile(tif, tile, buf, buf_size);
    if (read_size == static_cast<tmsize_t>(-1)) {
        // Handle error
        free(buf);
        FreeTIFFInMemory(tif);
        return 0;
    }

    // Call TIFFWriteRawTile
    tmsize_t write_size = TIFFWriteRawTile(tif, tile, buf, read_size);
    if (write_size == static_cast<tmsize_t>(-1)) {
        // Handle error
        free(buf);
        FreeTIFFInMemory(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    tmsize_t raw_read_size = TIFFReadRawTile(tif, tile, buf, buf_size);
    if (raw_read_size == static_cast<tmsize_t>(-1)) {
        // Handle error
        free(buf);
        FreeTIFFInMemory(tif);
        return 0;
    }

    // Free allocated resources
    free(buf);
    FreeTIFFInMemory(tif);

    return 0; // Success
}
