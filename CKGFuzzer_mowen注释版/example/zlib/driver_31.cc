#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to an integer
int safe_int_from_data(const uint8_t *data, size_t size, size_t offset, int min, int max) {
    if (offset + sizeof(int) > size) return min;
    int value = *reinterpret_cast<const int*>(data + offset);
    return (value < min) ? min : (value > max) ? max : value;
}

// Function to safely convert fuzz input to a string
const char* safe_string_from_data(const uint8_t *data, size_t size, size_t offset, size_t max_len) {
    if (offset + max_len > size) return nullptr;
    return reinterpret_cast<const char*>(data + offset);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 16) return 0;

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize gzFile
    gzFile gz_file = nullptr;

    // Extract parameters from fuzz input
    int windowBits = safe_int_from_data(data, size, 0, 8, 15);
    int level = safe_int_from_data(data, size, 4, 0, 9);
    int strategy = safe_int_from_data(data, size, 8, 0, Z_FIXED);
    const char* mode = safe_string_from_data(data, size, 12, 4);

    // Open a gzip file for reading or writing
    if (mode) {
        gz_file = gzopen("input_file", mode);
        if (!gz_file) return 0;
    }

    // Reset the inflate state with the specified window size and wrap mode
    int ret = inflateReset2(&strm, windowBits);
    if (ret != Z_OK) {
        if (gz_file) gzclose(gz_file);
        return 0;
    }

    // Adjust compression level and strategy for the deflate stream
    ret = deflateParams(&strm, level, strategy);
    if (ret != Z_OK) {
        if (gz_file) gzclose(gz_file);
        return 0;
    }

    // Rewind the file pointer to the beginning of the compressed file for reading
    if (gz_file) {
        ret = gzrewind(gz_file);
        if (ret != 0) {
            gzclose(gz_file);
            return 0;
        }
    }

    // Compute CRC-32 checksum for the input data
    unsigned long crc = crc32_z(0L, data, size);

    // Clean up resources
    if (gz_file) gzclose(gz_file);

    return 0;
}
