#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to perform meaningful operations
    if (size < sizeof(uint32_t) * 5) {
        return 0;
    }

    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF object in memory
    TIFF *tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        return 0;
    }

    // Initialize variables for API calls
    uint32_t tile = 0;
    uint32_t tile_size = TIFFTileSize(tif);
    void *tile_data = _TIFFmalloc(tile_size);
    if (!tile_data) {
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFSetClientInfo
    TIFFSetClientInfo(tif, nullptr, "FuzzClient");

    // Call TIFFReadDirectory
    if (TIFFReadDirectory(tif) != 1) {
        _TIFFfree(tile_data);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadRawTile
    if (TIFFReadRawTile(tif, tile, tile_data, tile_size) == -1) {
        _TIFFfree(tile_data);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFReadEncodedTile
    if (TIFFReadEncodedTile(tif, tile, tile_data, tile_size) == -1) {
        _TIFFfree(tile_data);
        TIFFClose(tif);
        return 0;
    }

    // Call TIFFWriteEncodedTile
    if (TIFFWriteEncodedTile(tif, tile, tile_data, tile_size) == -1) {
        _TIFFfree(tile_data);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    _TIFFfree(tile_data);
    TIFFClose(tif);
    return 0;
}
