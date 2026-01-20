#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object in memory from the fuzz input
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
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32_t) * 3 + sizeof(tmsize_t) * 2) {
        return 0;
    }

    // Create a TIFF object in memory from the fuzz input
    TIFF* tif = createTIFFInMemory(data, size);
    if (!tif) {
        return 0;
    }

    // Extract necessary parameters from the fuzz input
    uint32_t tile = *reinterpret_cast<const uint32_t*>(data);
    uint32_t tag = *reinterpret_cast<const uint32_t*>(data + sizeof(uint32_t));
    tmsize_t cc = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32_t) * 2);
    tmsize_t size_param = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32_t) * 2 + sizeof(tmsize_t));

    // Allocate buffers for reading and writing
    void* write_buf = malloc(cc);
    void* read_buf = malloc(size_param);
    if (!write_buf || !read_buf) {
        free(write_buf);
        free(read_buf);
        freeTIFF(tif);
        return 0;
    }

    // Initialize write buffer with some data (for demonstration purposes)
    memset(write_buf, 0xFF, cc);

    // Call TIFFSetField to set a TIFF tag
    if (TIFFSetField(tif, tag, 0) != 1) {
        // Handle error
        free(write_buf);
        free(read_buf);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFWriteRawTile to write raw tile data
    if (TIFFWriteRawTile(tif, tile, write_buf, cc) == (tmsize_t)(-1)) {
        // Handle error
        free(write_buf);
        free(read_buf);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFFlushData to ensure data is flushed
    if (TIFFFlushData(tif) != 1) {
        // Handle error
        free(write_buf);
        free(read_buf);
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFReadRawTile to read raw tile data
    if (TIFFReadRawTile(tif, tile, read_buf, size_param) == (tmsize_t)(-1)) {
        // Handle error
        free(write_buf);
        free(read_buf);
        freeTIFF(tif);
        return 0;
    }

    // Free allocated resources
    free(write_buf);
    free(read_buf);
    freeTIFF(tif);

    return 0;
}
