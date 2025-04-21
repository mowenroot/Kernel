#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to avoid buffer overflows
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Create a std::istringstream from the fuzz input data
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));

    // Create a TIFF object in memory using the string stream
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
    if (!tif) {
        return 0;
    }

    // Initialize variables for directory operations
    uint16_t dirn = *((uint16_t*)data);
    data += sizeof(uint16_t);
    size -= sizeof(uint16_t);

    // Create a custom directory
    TIFFCreateCustomDirectory(tif, nullptr);

    // Set the directory to the specified index
    TIFFSetDirectory(tif, dirn);

    // Read the directory to process its entries
    TIFFReadDirectory(tif);

    // Create a new directory
    TIFFCreateDirectory(tif);

    // Write the directory to the TIFF file
    TIFFWriteDirectory(tif);

    // Free the directory resources
    TIFFFreeDirectory(tif);

    // Close the TIFF object
    TIFFClose(tif);

    return 0;
}
