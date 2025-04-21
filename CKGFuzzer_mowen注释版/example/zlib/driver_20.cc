#include <stdio.h>  // Include for stderr and stdout
#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize variables
    gzFile file = gzopen("output_file", "wb");
    if (!file) {
        return 0;
    }

    int level = data[0] % 10; // Compression level (0-9)
    int strategy = data[1] % 3; // Compression strategy (0-2)
    int flush = data[2] % 4; // Flush mode (0-3)

    // Set compression parameters
    if (gzsetparams(file, level, strategy) != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Write data to the file
    if (gzwrite(file, data + 3, size - 3) <= 0) {
        gzclose(file);
        return 0;
    }

    // Flush the data
    if (gzflush(file, flush) != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Compute CRC32 checksum
    unsigned long crc = crc32_z(0L, nullptr, 0);
    crc = crc32_z(crc, data, size);

    // Check for errors
    int errnum;
    const char* error_msg = gzerror(file, &errnum);
    if (errnum != Z_OK) {
        fprintf(stderr, "Error: %s\n", error_msg);
    }

    // Close the file
    gzclose(file);

    return 0;
}
