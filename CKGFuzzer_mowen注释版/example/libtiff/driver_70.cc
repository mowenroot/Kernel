#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to convert fuzz input to a TIFF stream
TIFF* CreateTIFFStream(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("mem", &s); // Pass the address of the istringstream
    if (!tif) {
        TIFFErrorExt(0, "CreateTIFFStream", "Failed to create TIFF stream");
    }
    return tif;
}

// Function to free the TIFF stream
void FreeTIFFStream(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    TIFFRGBAImage img;
    char emsg[1024];
    void* buf = nullptr;
    tmsize_t buf_size = 0;
    int result = 0;

    // Initialize TIFF stream from fuzz input
    tif = CreateTIFFStream(data, size);
    if (!tif) {
        return 0;
    }

    // Initialize TIFFRGBAImage structure
    if (!TIFFRGBAImageBegin(&img, tif, 0, emsg)) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFRGBAImageBegin failed: %s", emsg);
        goto cleanup;
    }

    // Allocate buffer for reading strips
    buf_size = TIFFStripSize(tif);
    if (buf_size <= 0) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "Invalid strip size");
        goto cleanup;
    }
    buf = malloc(buf_size);
    if (!buf) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "Failed to allocate buffer");
        goto cleanup;
    }

    // Read encoded strip
    if (TIFFReadEncodedStrip(tif, 0, buf, buf_size) == (tmsize_t)(-1)) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFReadEncodedStrip failed");
        goto cleanup;
    }

    // Write encoded tile
    if (TIFFWriteEncodedTile(tif, 0, buf, buf_size) == (tmsize_t)(-1)) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFWriteEncodedTile failed");
        goto cleanup;
    }

    // Flush data to ensure consistency
    if (TIFFFlushData(tif) != 1) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "TIFFFlushData failed");
        goto cleanup;
    }

    result = 1;

cleanup:
    // Free allocated resources
    if (buf) {
        free(buf);
    }
    TIFFRGBAImageEnd(&img);
    FreeTIFFStream(tif);

    return result;
}
