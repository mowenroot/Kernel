#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (dest && src && n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely set a field
int safe_TIFFSetField(TIFF* tif, uint32 tag, ...) {
    va_list ap;
    va_start(ap, tag);
    int result = TIFFVSetField(tif, tag, ap);
    va_end(ap);
    if (result != 1) {
        fprintf(stderr, "TIFFSetField failed\n");
    }
    return result;
}

// Function to safely write raw tile data
tmsize_t safe_TIFFWriteRawTile(TIFF* tif, uint32 tile, void* data, tmsize_t cc) {
    tmsize_t result = TIFFWriteRawTile(tif, tile, data, cc);
    if (result == (tmsize_t)(-1)) {
        fprintf(stderr, "TIFFWriteRawTile failed\n");
    }
    return result;
}

// Function to safely read raw tile data
tmsize_t safe_TIFFReadRawTile(TIFF* tif, uint32 tile, void* buf, tmsize_t size) {
    tmsize_t result = TIFFReadRawTile(tif, tile, buf, size);
    if (result == (tmsize_t)(-1)) {
        fprintf(stderr, "TIFFReadRawTile failed\n");
    }
    return result;
}

// Function to safely flush data
int safe_TIFFFlushData(TIFF* tif) {
    int result = TIFFFlushData(tif);
    if (result != 1) {
        fprintf(stderr, "TIFFFlushData failed\n");
    }
    return result;
}

// Function to safely set client info
void safe_TIFFSetClientInfo(TIFF* tif, void* data, const char* name) {
    TIFFSetClientInfo(tif, data, name);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < sizeof(uint32_t) * 3 + sizeof(tmsize_t) * 2) {
        return 0;
    }

    // Convert fuzz input to a string for in-memory TIFF operations
    std::string tiffDataStr(reinterpret_cast<const char*>(data), size);
    std::istringstream tiffData(tiffDataStr);

    // Initialize variables
    TIFF* tif = TIFFStreamOpen("MemTIFF", &tiffData);
    if (!tif) {
        fprintf(stderr, "TIFFStreamOpen failed\n");
        return 0;
    }

    // Extract necessary data from the fuzz input
    uint32_t tag = *((uint32_t*)data);
    uint32_t tile = *((uint32_t*)(data + sizeof(uint32_t)));
    tmsize_t cc = *((tmsize_t*)(data + sizeof(uint32_t) * 2));
    tmsize_t size_to_read = *((tmsize_t*)(data + sizeof(uint32_t) * 2 + sizeof(tmsize_t)));

    // Allocate buffers
    void* write_buffer = safe_malloc(cc);
    void* read_buffer = safe_malloc(size_to_read);

    // Set client info
    safe_TIFFSetClientInfo(tif, write_buffer, "WriteBuffer");
    safe_TIFFSetClientInfo(tif, read_buffer, "ReadBuffer");

    // Set field
    safe_TIFFSetField(tif, tag, tile, cc, size_to_read);

    // Write raw tile data
    safe_TIFFWriteRawTile(tif, tile, write_buffer, cc);

    // Flush data
    safe_TIFFFlushData(tif);

    // Read raw tile data
    safe_TIFFReadRawTile(tif, tile, read_buffer, size_to_read);

    // Clean up
    safe_free(write_buffer);
    safe_free(read_buffer);
    TIFFClose(tif);

    return 0;
}
