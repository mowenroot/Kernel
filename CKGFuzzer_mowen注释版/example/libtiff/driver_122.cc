#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Custom warning handler function
static void CustomWarningHandler(thandle_t clientdata, const char* module, const char* fmt, va_list ap) {
    // Custom warning handling logic can be added here
    vfprintf(stderr, fmt, ap);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32_t) + sizeof(uint16_t) + sizeof(tmsize_t)) {
        return 0;
    }

    // Convert fuzz input to a string
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));

    // Initialize TIFF structure
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s);
    if (!tif) {
        return 0;
    }

    // Set custom warning handler
    TIFFSetWarningHandlerExt(CustomWarningHandler);

    // Retrieve client data
    thandle_t clientdata = TIFFClientdata(tif);

    // Read raw tile data
    uint32 tile = *((uint32_t*)data);
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    void* buf = malloc(size);
    if (!buf) {
        TIFFClose(tif);
        return 0;
    }

    tmsize_t readSize = TIFFReadRawTile(tif, tile, buf, size);
    if (readSize == (tmsize_t)(-1)) {
        free(buf);
        TIFFClose(tif);
        return 0;
    }

    // Swap byte order of the read data
    TIFFSwabArrayOfShort((uint16_t*)buf, readSize / sizeof(uint16_t));

    // Read custom directory
    toff_t diroff = *((toff_t*)data);
    data += sizeof(toff_t);
    size -= sizeof(toff_t);

    // Assuming TIFFFieldArray is a known size, replace with actual size if known
    const size_t TIFFFieldArraySize = 100; // Example size, replace with actual size if known
    const TIFFFieldArray* infoarray = (const TIFFFieldArray*)data;
    data += TIFFFieldArraySize;
    size -= TIFFFieldArraySize;

    int result = TIFFReadCustomDirectory(tif, diroff, infoarray);
    if (result != 1) {
        free(buf);
        TIFFClose(tif);
        return 0;
    }

    // Clean up
    free(buf);
    TIFFClose(tif);

    return 0;
}
