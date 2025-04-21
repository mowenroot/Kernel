#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF stream in memory
TIFF* createInMemoryTIFF(const uint8_t* data, size_t size) {
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
    uint32_t tile = 0;
    uint32_t row = 0;
    uint16_t sample = 0;
    void* buf = nullptr;
    tmsize_t bufSize = 0;
    int result = 0;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32_t) * 3 + sizeof(uint16_t)) {
        return 0;
    }

    // Create a TIFF object from the fuzz input
    tif = createInMemoryTIFF(data, size);
    if (!tif) {
        return 0;
    }

    // Extract parameters from the fuzz input
    tile = *reinterpret_cast<const uint32_t*>(data);
    row = *reinterpret_cast<const uint32_t*>(data + sizeof(uint32_t));
    sample = *reinterpret_cast<const uint16_t*>(data + sizeof(uint32_t) * 2);
    bufSize = *reinterpret_cast<const tmsize_t*>(data + sizeof(uint32_t) * 2 + sizeof(uint16_t));

    // Allocate buffer for reading/writing operations
    buf = malloc(bufSize);
    if (!buf) {
        freeTIFF(tif);
        return 0;
    }

    // Call TIFFFindField to find a field based on the fuzz input
    const TIFFField* field = TIFFFindField(tif, tile, TIFF_ANY);
    if (field) {
        // Perform operations based on the found field
        // Example: Log the found field (for debugging purposes)
        // printf("Found field: tag=%u, type=%u\n", field->field_tag, field->field_type);
    }

    // Call TIFFReadEncodedTile with the fuzz input
    tmsize_t readSize = TIFFReadEncodedTile(tif, tile, buf, bufSize);
    if (readSize == (tmsize_t)(-1)) {
        // Handle error
        // printf("TIFFReadEncodedTile failed\n");
    }

    // Call TIFFWriteEncodedTile with the fuzz input
    tmsize_t writeSize = TIFFWriteEncodedTile(tif, tile, buf, bufSize);
    if (writeSize == (tmsize_t)(-1)) {
        // Handle error
        // printf("TIFFWriteEncodedTile failed\n");
    }

    // Call TIFFReadScanline with the fuzz input
    result = TIFFReadScanline(tif, buf, row, sample);
    if (result == -1) {
        // Handle error
        // printf("TIFFReadScanline failed\n");
    }

    // Call TIFFFlushData to ensure data integrity
    result = TIFFFlushData(tif);
    if (result == 0) {
        // Handle error
        // printf("TIFFFlushData failed\n");
    }

    // Free allocated resources
    free(buf);
    freeTIFF(tif);

    return 0;
}
