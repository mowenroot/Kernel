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

// Function to create a TIFF object in memory from a string
TIFF* CreateTIFFInMemory(const std::string& data) {
    std::istringstream s(data); // Use std::istringstream instead of std::stringstream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the stream
    if (!tif) {
        return nullptr;
    }
    return tif;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzz_input = FuzzInputToString(data, size);

    // Create a TIFF object in memory
    TIFF* tif = CreateTIFFInMemory(fuzz_input);
    if (!tif) {
        return 0;
    }

    // Initialize variables
    uint64_t* long_array = nullptr;
    tmsize_t long_array_size = 0;
    uint32_t tile_index = 0;
    void* tile_data = nullptr;
    tmsize_t tile_data_size = 0;
    int compression_scheme = 0;
    uint16_t directory_index = 0;

    // Ensure proper bounds checking before accessing arrays or performing pointer arithmetic
    if (size >= sizeof(uint64_t) && size >= sizeof(uint32_t) && size >= sizeof(int) && size >= sizeof(uint16_t)) {
        // Derive API inputs from fuzz driver inputs
        long_array_size = size / sizeof(uint64_t);
        long_array = static_cast<uint64_t*>(malloc(long_array_size * sizeof(uint64_t)));
        if (long_array) {
            memcpy(long_array, data, long_array_size * sizeof(uint64_t));
        }

        tile_index = *reinterpret_cast<const uint32_t*>(data + long_array_size * sizeof(uint64_t));
        tile_data_size = size - (long_array_size * sizeof(uint64_t) + sizeof(uint32_t));
        tile_data = malloc(tile_data_size);
        if (tile_data) {
            memcpy(tile_data, data + long_array_size * sizeof(uint64_t) + sizeof(uint32_t), tile_data_size);
        }

        compression_scheme = *reinterpret_cast<const int*>(data + long_array_size * sizeof(uint64_t) + sizeof(uint32_t) + tile_data_size);
        directory_index = *reinterpret_cast<const uint16_t*>(data + long_array_size * sizeof(uint64_t) + sizeof(uint32_t) + tile_data_size + sizeof(int));
    }

    // Call TIFFSwabArrayOfLong8
    if (long_array) {
        TIFFSwabArrayOfLong8(long_array, long_array_size);
    }

    // Call TIFFSetField to set the compression scheme
    if (TIFFSetField(tif, TIFFTAG_COMPRESSION, compression_scheme) != 1) {
        // Handle error
    }

    // Call TIFFWriteRawTile
    if (tile_data) {
        if (TIFFWriteRawTile(tif, tile_index, tile_data, tile_data_size) == static_cast<tmsize_t>(-1)) {
            // Handle error
        }
    }

    // Call TIFFReadRawTile
    if (tile_data) {
        if (TIFFReadRawTile(tif, tile_index, tile_data, tile_data_size) == static_cast<tmsize_t>(-1)) {
            // Handle error
        }
    }

    // Call TIFFUnlinkDirectory
    if (TIFFUnlinkDirectory(tif, directory_index) != 1) {
        // Handle error
    }

    // Free allocated resources
    if (long_array) {
        free(long_array);
    }
    if (tile_data) {
        free(tile_data);
    }

    // Close the TIFF object
    TIFFClose(tif);

    return 0;
}
