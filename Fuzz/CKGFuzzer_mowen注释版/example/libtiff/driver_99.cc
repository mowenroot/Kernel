#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::ostringstream

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely reallocate memory
void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(ptr);
        exit(1);
    }
    return new_ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (memcpy(dest, src, n) != dest) {
        fprintf(stderr, "Memory copy failed\n");
        exit(1);
    }
}

// Function to safely set memory
void safe_memset(void* s, int c, size_t n) {
    if (memset(s, c, n) != s) {
        fprintf(stderr, "Memory set failed\n");
        exit(1);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(uint64_t) * 2 + sizeof(uint32_t) * 2 + sizeof(tmsize_t) * 2) {
        return 0;
    }

    // Initialize variables
    std::ostringstream oss; // Create a std::ostringstream object
    TIFF* tif = TIFFStreamOpen("memory", &oss); // Pass the address of the ostringstream object
    if (!tif) {
        fprintf(stderr, "Failed to open TIFF stream\n");
        return 1;
    }

    uint64_t* long_array = (uint64_t*)safe_malloc(sizeof(uint64_t) * 2);
    uint32_t tile_index = *(uint32_t*)(data + sizeof(uint64_t) * 2);
    tmsize_t tile_size = *(tmsize_t*)(data + sizeof(uint64_t) * 2 + sizeof(uint32_t));
    tmsize_t read_size = *(tmsize_t*)(data + sizeof(uint64_t) * 2 + sizeof(uint32_t) + sizeof(tmsize_t));

    // Copy data to long_array
    safe_memcpy(long_array, data, sizeof(uint64_t) * 2);

    // Perform byte swapping
    TIFFSwabArrayOfLong8(long_array, 2);

    // Write raw tile data
    tmsize_t write_result = TIFFWriteRawTile(tif, tile_index, long_array, tile_size);
    if (write_result == (tmsize_t)(-1)) {
        fprintf(stderr, "Failed to write raw tile\n");
        TIFFClose(tif);
        safe_free(long_array);
        return 1;
    }

    // Flush data to ensure consistency
    int flush_result = TIFFFlushData(tif);
    if (flush_result == 0) {
        fprintf(stderr, "Failed to flush data\n");
        TIFFClose(tif);
        safe_free(long_array);
        return 1;
    }

    // Read raw tile data
    uint64_t* read_buffer = (uint64_t*)safe_malloc(read_size);
    tmsize_t read_result = TIFFReadRawTile(tif, tile_index, read_buffer, read_size);
    if (read_result == (tmsize_t)(-1)) {
        fprintf(stderr, "Failed to read raw tile\n");
        TIFFClose(tif);
        safe_free(long_array);
        safe_free(read_buffer);
        return 1;
    }

    // Retrieve unmap file procedure
    TIFFUnmapFileProc unmap_proc = TIFFGetUnmapFileProc(tif);
    if (!unmap_proc) {
        fprintf(stderr, "Failed to get unmap file procedure\n");
        TIFFClose(tif);
        safe_free(long_array);
        safe_free(read_buffer);
        return 1;
    }

    // Clean up
    TIFFClose(tif);
    safe_free(long_array);
    safe_free(read_buffer);

    return 0;
}
