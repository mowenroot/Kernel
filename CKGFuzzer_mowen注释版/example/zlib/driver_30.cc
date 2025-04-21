#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a buffer
uint8_t* safe_malloc(size_t size) {
    if (size == 0) return nullptr;
    uint8_t* buf = (uint8_t*)malloc(size);
    if (!buf) return nullptr;
    return buf;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for file mode and buffer size
    if (size < 2) return 0;

    // Extract file mode (assuming it's a single byte)
    const char* mode = (data[0] == 'r') ? "rb" : "wb";

    // Extract buffer size (assuming it's a single byte)
    size_t buf_size = data[1];
    if (buf_size == 0) return 0; // Avoid zero-sized buffer

    // Skip the first two bytes for the actual data
    data += 2;
    size -= 2;

    // Open the gzip file
    gzFile file = gzopen("input_file", mode);
    if (!file) return 0; // Failed to open file

    // Allocate buffer for reading/writing
    uint8_t* buf = safe_malloc(buf_size);
    if (!buf) {
        gzclose_r(file);
        return 0;
    }

    // Perform operations based on the mode
    if (mode[0] == 'r') {
        // Read from the file
        int bytes_read = gzread(file, buf, buf_size);
        if (bytes_read < 0) {
            free(buf);
            gzclose_r(file);
            return 0;
        }

        // Compute CRC32 of the read data
        unsigned long crc = crc32_z(0L, buf, bytes_read);
        (void)crc; // Suppress unused variable warning
    } else {
        // Write to the file
        int bytes_written = gzwrite(file, data, size);
        if (bytes_written < 0) {
            free(buf);
            gzclose_r(file);
            return 0;
        }

        // Set compression parameters (example: level 6, default strategy)
        int level = 6;
        int strategy = Z_DEFAULT_STRATEGY;
        int result = gzsetparams(file, level, strategy);
        if (result != Z_OK) {
            free(buf);
            gzclose_r(file);
            return 0;
        }
    }

    // Close the file
    int close_result = gzclose_r(file);
    if (close_result != Z_OK) {
        free(buf);
        return 0;
    }

    // Free allocated memory
    free(buf);

    return 0;
}
